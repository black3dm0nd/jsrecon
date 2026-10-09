#!/usr/bin/env python3
"""
jsrecon — client-side attack-surface mapper for web pentests & bug bounty.
                                                            by black3dm0nd

Beautifies JavaScript and extracts hard-coded secrets, API endpoints, paths,
parameters, domains, internal IPs, S3 buckets, high-confidence DOM-XSS and
client-side misconfigurations. Findings are de-duplicated across every file,
tagged with their source file and a one-line exploitation hint, and exported to
text / html / json / csv / xml.

Signal over noise: DOM-XSS needs a source AND a sink in the same file; cleartext
HTTP must hit the in-scope domain; low-confidence entropy guesses are opt-in.

AUTHORISED TESTING ONLY. For discovered secrets, prefer read-only validation.

Examples:
  jsrecon.py -i app.min.js                          scan one bundle
  jsrecon.py -u https://t/ --crawl -o report.html   crawl a site -> HTML report
  jsrecon.py -u https://t/ --crawl --stealth -s     quiet, paced, triage view
  jsrecon.py -u https://t/ --extract -o urls.txt    list JS URLs, don't scan
  jsrecon.py -u https://t/app.js --source-maps      recover & scan original src
  jsrecon.py -l scripts.txt -o out.json --rules r.json
  cat app.js | jsrecon.py --secrets -f json         read stdin, secrets only
"""

import argparse
import os
import re
import sys

# Allow running as a script from anywhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (  # noqa: E402
    __version__, beautifier, discovery, fetcher, reporter,
)
from core.extractor import (  # noqa: E402
    ALL_CATEGORIES, CAT_SOURCEMAPS, Extractor, Finding, aggregate,
)
from core.patterns import SEV_MEDIUM  # noqa: E402

BANNER = r"""
     _
    (_)___ _ __ ___  ___ ___  _ __
    | / __| '__/ _ \/ __/ _ \| '_ \
    | \__ \ | |  __/ (_| (_) | | | |
   _/ |___/_|  \___|\___\___/|_| |_|
  |__/   JavaScript recon & secret miner  v%s
                                by black3dm0nd
""" % __version__

# Category filter flag -> what it surfaces (also used for the help text).
CATEGORY_HELP = {
    "secrets": "keys, tokens, passwords, connection strings",
    "vulns": "DOM-XSS & client-side misconfigurations",
    "dom": "potential DOM-based XSS (source -> sink)",
    "sourcemaps": "source maps found / recovered",
    "links": "URLs & endpoints",
    "dirs": "directories / path prefixes",
    "params": "query-string parameter names",
    "domains": "domains & subdomains",
    "ips": "IPv4 addresses (private ranges flagged)",
    "emails": "email addresses",
    "s3": "S3 bucket URLs",
    "comments": "revealing developer comments",
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="jsrecon.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )

    src = p.add_argument_group(
        "input", "At least one of -i/-u/-l, or pipe JavaScript via stdin.")
    src.add_argument("-i", "--input", action="append", default=[], metavar="FILE",
                     help="local JS file (repeatable)")
    src.add_argument("-u", "--url", action="append", default=[], metavar="URL",
                     help="remote JS URL, or an HTML page with --crawl (repeatable)")
    src.add_argument("-l", "--list", dest="list_file", metavar="FILE",
                     help="file with one URL or path per line")

    disc = p.add_argument_group("discovery (for URL targets)")
    disc.add_argument("--crawl", action="store_true",
                      help="treat URLs as HTML pages and recursively find + scan "
                           "the JS they load (script src, inline, dynamic "
                           "imports, webpack chunks)")
    disc.add_argument("--extract", action="store_true",
                      help="inventory mode: just list the referenced JS URLs and "
                           "exit — do not fetch or scan them")
    disc.add_argument("--source-maps", dest="source_maps", action="store_true",
                      help="recover and scan original pre-minification source "
                           "from each bundle's .map (sourceMappingURL)")
    disc.add_argument("--depth", type=int, default=3, metavar="N",
                      help="--crawl recursion depth, i.e. JS->JS levels (default 3)")
    disc.add_argument("--max-files", type=int, default=300, metavar="N",
                      help="cap on files fetched while crawling (default 300)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="PATH",
                     help="write the report to PATH. If PATH ends in a known "
                          "extension (.txt/.html/.json/.csv/.xml) the format is "
                          "taken from it — no -f needed (e.g. -o report.html). "
                          "Otherwise PATH is a basename and one file per -f format "
                          "is written. Prints to stdout when omitted.")
    out.add_argument("-f", "--format", default="txt",
                     help="comma-separated report format(s): txt, html, json, csv, "
                          "xml (default: txt). Ignored when -o carries an extension.")
    out.add_argument("--no-color", action="store_true",
                     help="disable ANSI colour in terminal output")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="suppress the banner and progress output on stderr")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="show the affected file(s) for every finding, including "
                          "the INFO inventory (links, directories, domains, …)")
    out.add_argument("--group", choices=["source", "category"], default=None,
                     help="organise findings per 'source' file, or aggregate and "
                          "de-duplicate across all files by 'category' "
                          "(default: category).")
    out.add_argument("-s", "--summary", action="store_true",
                     help="compact view: counts + only critical/high findings "
                          "(txt/html); json/csv stay complete")
    out.add_argument("--max-per-category", type=int, default=0, metavar="N",
                     help="show at most N findings per category in txt/html "
                          "(0 = no limit; the rest noted as '… and X more')")

    filt = p.add_argument_group(
        "filters", "All categories are shown unless you pick some (then only "
                   "those are shown).")
    for name, desc in CATEGORY_HELP.items():
        filt.add_argument(f"--{name}", action="store_true", help=desc)
    filt.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"],
                      default="info", metavar="LEVEL",
                      help="drop findings below LEVEL (critical|high|medium|low|info)")
    filt.add_argument("--entropy", action="store_true",
                      help="also flag high-entropy strings as possible secrets "
                           "(off by default — low-confidence / noisy)")
    filt.add_argument("--scope", metavar="DOMAIN[,...]",
                      help="in-scope domain(s) for the Insecure-HTTP check; "
                           "auto-derived from URL targets, set it for local files")
    filt.add_argument("--rules", metavar="FILE",
                      help="JSON file of custom secret patterns and/or exclude "
                           "regexes (see README)")
    filt.add_argument("--exclude", action="append", default=[], metavar="REGEX",
                      help="drop any finding whose value matches REGEX "
                           "(repeatable; combined with the rules file's excludes)")

    net = p.add_argument_group("network (for URL targets)")
    net.add_argument("-H", "--header", action="append", default=[],
                     metavar="'NAME: VALUE'", help="extra request header (repeatable)")
    net.add_argument("-b", "--cookie", metavar="STR", help="Cookie header value")
    net.add_argument("--proxy", metavar="URL",
                     help="proxy, e.g. http://127.0.0.1:8080 (Burp)")
    net.add_argument("-k", "--insecure", action="store_true",
                     help="skip TLS certificate verification")
    net.add_argument("-t", "--timeout", type=int, default=fetcher.DEFAULT_TIMEOUT,
                     metavar="SEC", help=f"request timeout (default {fetcher.DEFAULT_TIMEOUT})")
    net.add_argument("--threads", type=int, default=5, metavar="N",
                     help="concurrent fetches (default 5; forced to 1 by --stealth)")

    stealth = p.add_argument_group("stealth")
    stealth.add_argument("--stealth", action="store_true",
                         help="blend in: rotate browser User-Agents, send browser "
                              "headers + Referer, 1 connection, randomised delay "
                              "(sets --delay 0.75 --jitter 1.5 unless overridden)")
    stealth.add_argument("--delay", type=float, default=None, metavar="SEC",
                         help="base wait before each request (default 0)")
    stealth.add_argument("--jitter", type=float, default=None, metavar="SEC",
                         help="extra random 0..SEC per request (default 0)")

    p.add_argument("-V", "--version", action="version",
                   version=f"jsrecon {__version__}")
    return p


def resolve_categories(args):
    """Categories to run: the ones selected, or all of them if none selected."""
    chosen = {name for name in CATEGORY_HELP if getattr(args, name)}
    return chosen or set(ALL_CATEGORIES)


def parse_headers(items):
    headers = {}
    for h in items:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def load_rules(path):
    """Load a JSON rules file -> (extra_secret_patterns, exclude_regexes).

    Schema:
      {
        "secrets": [{"name": str, "regex": str, "severity": str?, "group": int?}],
        "exclude": ["regex", ...]
      }
    """
    import json
    from core.patterns import SEVERITY_ORDER, SEV_MEDIUM
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        sys.exit(f"[!] could not read rules file {path}: {e}")

    extra_secrets, excludes = [], []
    for i, r in enumerate(data.get("secrets", [])):
        name, pat = r.get("name"), r.get("regex")
        if not name or not pat:
            sys.exit(f"[!] rules: secrets[{i}] needs both 'name' and 'regex'")
        sev = (r.get("severity") or SEV_MEDIUM).lower()
        if sev not in SEVERITY_ORDER:
            sys.exit(f"[!] rules: secrets[{i}] bad severity '{sev}'")
        try:
            rx = re.compile(pat)
        except re.error as e:
            sys.exit(f"[!] rules: secrets[{i}] invalid regex: {e}")
        extra_secrets.append((name, rx, sev, int(r.get("group", 0))))
    for pat in data.get("exclude", []):
        try:
            excludes.append(re.compile(pat))
        except re.error as e:
            sys.exit(f"[!] rules: invalid exclude regex {pat!r}: {e}")
    return extra_secrets, excludes


def filter_by_severity(findings, min_sev):
    from core.patterns import SEVERITY_ORDER
    thresh = SEVERITY_ORDER[min_sev]
    return [f for f in findings if SEVERITY_ORDER[f.severity] <= thresh]


def log(msg, quiet):
    if not quiet:
        sys.stderr.write(msg + "\n")


def crawl_pages(loaded, fetch_kw, threads, depth, max_files, quiet):
    """Recursively expand HTML pages into the JavaScript they load.

    Follows <script src>, inline scripts, dynamic imports and webpack chunks up
    to *depth* JS→JS levels, capped at *max_files* fetches. Returns
    (to_scan, extra): the ordered Sources to analyse, and extra[origin] holding
    discovery Findings (discovered-JS links) to merge in later.
    """
    to_scan = []
    extra = {}
    fetched_urls = set()          # every URL we've already requested
    budget = {"n": max_files}

    def fetch_new(urls, referer=None):
        """Fetch only not-yet-seen URLs, honouring the budget.

        *referer* is set to the page/script that linked these resources so each
        request carries a natural Referer (used by --stealth).
        """
        wanted = []
        for u in urls:
            if u in fetched_urls or budget["n"] <= 0:
                continue
            fetched_urls.add(u)
            budget["n"] -= 1
            wanted.append(u)
        if not wanted:
            return []
        kw = dict(fetch_kw, referer=referer)
        return fetcher.load_targets(targets=wanted, threads=threads, **kw)

    # Level 0: classify initial inputs; mine HTML pages, keep JS for recursion.
    mine_next = []   # JS Sources whose contents we will scan for further refs
    for src in loaded:
        if fetcher.is_url(src.origin):
            fetched_urls.add(src.origin)
        if fetcher.is_url(src.origin) and src.ok and discovery.looks_like_html(src.content):
            links = discovery.find_js_links(src.content, src.origin)
            log(f"[*] {src.origin}: {len(links)} JS file(s)", quiet)
            # Scan the page's inline scripts as ONE source (not the raw HTML, and
            # not one source per block) — avoids markup noise, double-counting and
            # empty "inline #N" entries.
            inline_code = "\n".join(discovery.find_inline_scripts(src.content)).strip()
            if len(inline_code) >= 40:
                to_scan.append(fetcher.Source(f"{src.origin} (inline scripts)",
                                              inline_code))
            got = fetch_new(links, referer=src.origin)
            to_scan.extend(got)
            mine_next.extend(s for s in got if s.ok)
        else:
            to_scan.append(src)
            if fetcher.is_url(src.origin) and src.ok:
                mine_next.append(src)

    # Levels 1..depth: follow JS→JS references (chunks, imports, webpack chunks).
    level = 1
    while level <= depth and mine_next and budget["n"] > 0:
        found = []
        current, mine_next = mine_next, []
        for src in current:
            refs = discovery.find_js_refs_in_js(src.content, src.origin)
            refs = [u for u in refs if u not in fetched_urls]
            if not refs:
                continue
            got = fetch_new(refs, referer=src.origin)
            to_scan.extend(got)
            found.extend(s for s in got if s.ok)
        if found:
            log(f"[*] depth {level}: discovered {len(found)} more JS file(s)", quiet)
        mine_next = found
        level += 1

    if budget["n"] <= 0:
        log(f"[i] --max-files cap reached; some chunks may be unscanned.", quiet)
    return to_scan, extra


def recover_source_maps(to_scan, categories, fetch_kw, quiet):
    """For each JS source with a sourceMappingURL, recover original sources.

    Returns (extra_map_findings, recovered_sources).
    """
    extra = {}
    recovered = []
    for src in list(to_scan):
        if not src.ok or not src.content:
            continue
        raw = discovery.find_sourcemap_url(src.content)
        if not raw:
            continue

        map_text, map_label = None, raw
        if raw.startswith("data:"):
            kind, payload = discovery.resolve_sourcemap(raw, "")
            map_text, map_label = payload, "inline data: URI"
        elif fetcher.is_url(src.origin):
            _, abs_url = discovery.resolve_sourcemap(raw, src.origin)
            msrc = fetcher.fetch_url(abs_url, **fetch_kw)
            if msrc.ok:
                map_text, map_label = msrc.content, abs_url
            else:
                log(f"[!] source map {abs_url}: {msrc.error}", quiet)
        else:  # local file: look for the .map next to it
            cand = os.path.join(os.path.dirname(src.origin), raw)
            if os.path.exists(cand):
                msrc = fetcher.read_local(cand)
                if msrc.ok:
                    map_text, map_label = msrc.content, cand

        if not map_text:
            continue

        rec = discovery.recover_sources(map_text, map_label)
        log(f"[+] {src.origin}: recovered {len(rec)} source(s) from map", quiet)
        if CAT_SOURCEMAPS in categories:
            extra.setdefault(src.origin, []).append(Finding(
                CAT_SOURCEMAPS, "source-map", map_label, SEV_MEDIUM,
                note=f"{len(rec)} original source(s) recovered"))
        for label, content in rec:
            recovered.append(fetcher.Source(label, content))
    return extra, recovered


def merge(dst, src):
    for k, v in src.items():
        dst.setdefault(k, []).extend(v)


def _host_of(s):
    """Hostname of a URL, or '' for non-URLs."""
    if not s or "://" not in s:
        return ""
    from urllib.parse import urlparse
    try:
        return (urlparse(s).hostname or "").lower()
    except ValueError:
        return ""


def run_extract(loaded, formats, args):
    """--extract: emit a de-duplicated, importance-ranked list of the JS file
    URLs referenced by the inputs, without fetching or scanning them."""
    urls, seen = [], set()
    for src in loaded:
        if not src.ok:
            if src.error and not src.error.startswith("HTTP 404"):
                log(f"[!] {src.origin}: {src.error}", args.quiet)
            continue
        if fetcher.is_url(src.origin) and discovery.looks_like_html(src.content):
            refs = discovery.find_js_links(src.content, src.origin)
        else:
            base = src.origin if fetcher.is_url(src.origin) else ""
            refs = discovery.find_js_refs_in_js(src.content, base)
        for u in refs:
            if u not in seen:
                seen.add(u)
                urls.append(u)

    rank = {"high": 0, "medium": 1, "info": 2}
    urls.sort(key=lambda u: (rank.get(discovery.importance(u)[0], 3), u))
    log(f"[*] extracted {len(urls)} JavaScript URL(s) — not fetched "
        f"(enumerate manually, or re-run with --crawl to scan)", args.quiet)

    body = "\n".join(urls) + ("\n" if urls else "")
    if args.output:
        path = args.output if "." in args.output.rpartition("/")[2] else f"{args.output}.txt"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        log(f"[>] wrote {path}", args.quiet)
    else:
        sys.stdout.write(body)
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.quiet:
        sys.stderr.write(BANNER + "\n")

    categories = resolve_categories(args)

    # Custom rules (extra secret patterns + excludes) and --exclude regexes.
    extra_secrets, excludes = ([], [])
    if args.rules:
        extra_secrets, excludes = load_rules(args.rules)
    for pat in args.exclude:
        try:
            excludes.append(re.compile(pat))
        except re.error as e:
            sys.exit(f"[!] invalid --exclude regex {pat!r}: {e}")
    if extra_secrets or excludes:
        log(f"[*] rules: +{len(extra_secrets)} secret pattern(s), "
            f"{len(excludes)} exclude(s)", args.quiet)

    # Resolve output target and format. An extension on -o (e.g. report.html)
    # selects the format and the exact filename — no -f needed.
    out_ext = None
    if args.output:
        base, dot, ext = args.output.rpartition(".")
        if dot and ext.lower() in reporter.RENDERERS:
            out_ext = ext.lower()
    if out_ext:
        formats = [out_ext]
    else:
        formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    bad_fmt = [f for f in formats if f not in reporter.RENDERERS]
    if bad_fmt:
        sys.exit(f"[!] unknown format(s): {', '.join(bad_fmt)}; "
                 f"valid: {', '.join(reporter.RENDERERS)}")

    # Stealth resolves timing + concurrency defaults unless the user overrode them.
    delay = args.delay if args.delay is not None else (0.75 if args.stealth else 0.0)
    jitter = args.jitter if args.jitter is not None else (1.5 if args.stealth else 0.0)
    threads = 1 if args.stealth else args.threads   # serialise to 1 connection
    if args.stealth:
        log(f"[*] stealth: rotating UA, browser headers + Referer, 1 connection, "
            f"delay {delay}s +0..{jitter}s jitter", args.quiet)

    fetch_kw = dict(timeout=args.timeout, headers=parse_headers(args.header),
                    proxy=args.proxy, insecure=args.insecure, cookie=args.cookie,
                    stealth=args.stealth, delay=delay, jitter=jitter)

    # In-scope target domains (for the scope-sensitive Insecure-HTTP check):
    # explicit --scope plus the hosts of every URL target given.
    target_domains = set()
    if args.scope:
        target_domains.update(d.strip().lower() for d in args.scope.split(",") if d.strip())
    for t in list(args.url) + ([] if not args.list_file else []):
        h = _host_of(t)
        if h:
            target_domains.add(h)

    # --- gather sources ---------------------------------------------------
    loaded = []
    if (not args.input and not args.url and not args.list_file
            and not sys.stdin.isatty()):
        loaded.append(fetcher.read_stdin())          # JS piped on stdin

    if args.input or args.url or args.list_file:
        log(f"[*] loading targets (threads={threads})…", args.quiet)
        loaded.extend(fetcher.load_targets(
            targets=list(args.input) + list(args.url),
            list_file=args.list_file, threads=threads, **fetch_kw))
        for s in loaded:                       # learn scope from fetched URLs too
            h = _host_of(s.origin)
            if h:
                target_domains.add(h)

    if not loaded:
        sys.exit("[!] no input — pass -i/-u/-l or pipe JS via stdin (see -h).")

    # --- EXTRACT mode: list referenced JS URLs and exit (no content scan) --
    if args.extract:
        return run_extract(loaded, formats, args)

    # --- discovery / source-map expansion ---------------------------------
    extra = {}  # origin -> [discovery/source-map Findings]
    if args.crawl:
        to_scan, dextra = crawl_pages(loaded, fetch_kw, threads, args.depth,
                                      args.max_files, args.quiet)
        merge(extra, dextra)
    else:
        to_scan = list(loaded)

    if args.source_maps:
        mextra, recovered = recover_source_maps(to_scan, categories,
                                                fetch_kw, args.quiet)
        merge(extra, mextra)
        to_scan.extend(recovered)

    # --- analyse ----------------------------------------------------------
    extractor = Extractor(categories=categories,
                          verify_entropy=args.entropy,
                          target_domains=target_domains,
                          extra_secrets=extra_secrets,
                          exclude=excludes)

    results = []
    nonzero = 0
    for src in to_scan:
        if not src.ok:
            # Only surface real fetch errors, not empty/404 chunks.
            if src.error and not src.error.startswith("HTTP 404"):
                log(f"[!] {src.origin}: {src.error}", args.quiet)
            disc = extra.pop(src.origin, [])
            if disc:
                results.append((src.origin, filter_by_severity(disc, args.min_severity)))
            continue

        code = beautifier.beautify(src.content)
        findings = extractor.extract(code)
        findings.extend(extra.pop(src.origin, []))  # merge discovery findings
        findings = filter_by_severity(findings, args.min_severity)
        results.append((src.origin, findings))
        if findings:                               # no spam for empty sources
            nonzero += 1
            log(f"[+] {src.origin}: {len(findings)} findings", args.quiet)

    # Any discovery findings whose origin was never scanned (safety net).
    for origin, fnd in extra.items():
        results.append((origin, filter_by_severity(fnd, args.min_severity)))

    scanned = len(to_scan)
    log(f"[*] scanned {scanned} source(s); {nonzero} had findings", args.quiet)

    # --- grouping ---------------------------------------------------------
    # Aggregate + de-duplicate across all sources by default so identical
    # findings seen in many files collapse to one row (no repetition).
    group = args.group or "category"
    if group == "category":
        merged = aggregate(results)
        results = [(f"{scanned} source(s) — aggregated & de-duplicated", merged)]

    # --- report -----------------------------------------------------------
    meta = {
        "version": __version__,
        "generated": reporter._now(),
        "source_count": scanned,
        "summary": reporter.summarise(results),
        "summary_only": args.summary,
        "max_per_category": args.max_per_category,
        "group": group,
        "verbose": args.verbose,
    }

    color = (not args.no_color) and sys.stdout.isatty() and not args.output

    for fmt in formats:
        renderer = reporter.RENDERERS[fmt]
        if fmt == "txt":
            text = renderer(results, meta, color=color)
        else:
            text = renderer(results, meta)

        if args.output:
            # -o report.html -> exact path; -o report (+ -f) -> report.<fmt>
            path = args.output if out_ext else f"{args.output}.{fmt}"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            log(f"[>] wrote {path}", args.quiet)
        else:
            sys.stdout.write(text)
            if not text.endswith("\n"):
                sys.stdout.write("\n")

    # exit code: 1 if any critical/high finding, else 0 (CI-friendly)
    sev = meta["summary"]["by_severity"]
    return 1 if (sev.get("critical") or sev.get("high")) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
