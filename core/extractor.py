"""Extraction engine: turns beautified JS text into categorised findings."""

import ipaddress
import math
import re
from urllib.parse import urlparse

from . import patterns as P

# Category identifiers (also the CLI filter flag names).
CAT_SECRETS = "secrets"
CAT_LINKS = "links"
CAT_DIRS = "dirs"
CAT_PARAMS = "params"
CAT_DOMAINS = "domains"
CAT_IPS = "ips"
CAT_EMAILS = "emails"
CAT_S3 = "s3"
CAT_DOM = "dom"
CAT_VULNS = "vulns"
CAT_COMMENTS = "comments"
CAT_SOURCEMAPS = "sourcemaps"

ALL_CATEGORIES = [
    CAT_SECRETS, CAT_VULNS, CAT_DOM, CAT_SOURCEMAPS, CAT_LINKS, CAT_DIRS,
    CAT_PARAMS, CAT_DOMAINS, CAT_IPS, CAT_EMAILS, CAT_S3, CAT_COMMENTS,
]

CATEGORY_TITLES = {
    CAT_SOURCEMAPS: "Source Maps",
    CAT_SECRETS: "Secrets / Credentials / Keys / Tokens",
    CAT_LINKS: "Links & Endpoints",
    CAT_DIRS: "Directories / Paths",
    CAT_PARAMS: "Query Parameters",
    CAT_DOMAINS: "Domains & Subdomains",
    CAT_IPS: "IP Addresses",
    CAT_EMAILS: "Email Addresses",
    CAT_S3: "S3 Buckets",
    CAT_DOM: "Potential DOM-Based XSS",
    CAT_VULNS: "Vulnerabilities & Misconfigurations",
    CAT_COMMENTS: "Interesting Comments",
}


class Finding:
    __slots__ = ("category", "kind", "value", "severity", "line",
                 "note", "count", "sources")

    def __init__(self, category, kind, value, severity=P.SEV_INFO,
                 line=0, note=""):
        self.category = category
        self.kind = kind            # sub-type, e.g. "AWS Access Key ID"
        self.value = value
        self.severity = severity
        self.line = line
        self.note = note
        self.count = 1              # occurrences (after aggregation)
        self.sources = None         # list of origins (after aggregation)

    def key(self):
        # de-dup key: same category+kind+value collapses
        return (self.category, self.kind, self.value)

    def to_dict(self):
        d = {
            "category": self.category,
            "kind": self.kind,
            "value": self.value,
            "severity": self.severity,
            "line": self.line,
            "note": self.note,
        }
        if self.count > 1:
            d["count"] = self.count
        if self.sources is not None:
            d["sources"] = self.sources
        return d


def aggregate(results):
    """Collapse findings across all sources into one globally de-duplicated list.

    Identical findings (same category+kind+value) seen in many files become a
    single entry carrying an occurrence `count` and the list of `sources` it
    appeared in — the key to a readable crawl of dozens of chunks.
    """
    merged = {}
    for origin, findings in results:
        for f in findings:
            k = f.key()
            m = merged.get(k)
            if m is None:
                m = Finding(f.category, f.kind, f.value, f.severity,
                            f.line, f.note)
                m.count = 0
                m.sources = []
                merged[k] = m
            m.count += 1
            if origin not in m.sources:
                m.sources.append(origin)
            if P.SEVERITY_ORDER[f.severity] < P.SEVERITY_ORDER[m.severity]:
                m.severity = f.severity
    out = list(merged.values())
    out.sort(key=lambda f: (P.SEVERITY_ORDER[f.severity], f.category,
                            f.kind, f.value))
    return out


def _apex(host):
    """Naive registrable-domain guess: the last two labels of a hostname."""
    labels = (host or "").strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def iter_comments(text):
    """Yield (comment_text, start_pos) respecting string/template literals.

    A regex alone treats the '//' inside 'https://x' as a line comment; this
    simple scanner tracks quote state so only real comments are returned.
    """
    i, n = 0, len(text)
    in_str = None
    escaped = False
    while i < n:
        c = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == in_str:
                in_str = None
            i += 1
            continue
        if c in "\"'`":
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            yield text[i:j], i
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            yield text[i:j], i
            i = j
            continue
        i += 1


def _line_index(text):
    """Return a sorted list of line-start offsets for O(log n) line lookup."""
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def _line_of(starts, pos):
    # binary search
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1  # 1-based


class Extractor:
    # Shannon-entropy floor for the opt-in generic-secret detector.
    ENTROPY_THRESHOLD = 4.0

    def __init__(self, categories=None, verify_entropy=False,
                 target_domains=None, extra_secrets=None, exclude=None):
        self.categories = set(categories or ALL_CATEGORIES)
        self.verify_entropy = verify_entropy          # generic high-entropy guesses
        # hostnames considered in-scope for scope-sensitive checks (HTTP endpoint)
        self.target_domains = set(target_domains or ())
        # user-supplied secret patterns: list of (name, compiled, severity, group)
        self.extra_secrets = list(extra_secrets or ())
        # compiled regexes; a finding whose value matches any is dropped
        self.exclude = list(exclude or ())

    def want(self, cat):
        return cat in self.categories

    def _in_scope(self, host):
        """True if *host* shares a registrable domain with any target host."""
        host = (host or "").lower().strip(".")
        if not host:
            return False
        for t in self.target_domains:
            t = t.lower().strip(".")
            if host == t or host.endswith("." + t) or t.endswith("." + host):
                return True
            # compare the last two labels (apex) as a fallback
            if _apex(host) and _apex(host) == _apex(t):
                return True
        return False

    def extract(self, text):
        findings = []
        starts = _line_index(text)

        def emit(cat, kind, value, sev, pos, note=""):
            value = value.strip()
            if not value:
                return
            if any(rx.search(value) for rx in self.exclude):
                return                          # user --exclude / rules suppression
            findings.append(Finding(
                category=cat, kind=kind, value=value, severity=sev,
                line=_line_of(starts, pos), note=note,
            ))

        # -- secrets ---------------------------------------------------------
        if self.want(CAT_SECRETS):
            builtin = [(n, rx, sev, grp, False) for n, rx, sev, grp in P.SECRET_PATTERNS]
            custom = [(n, rx, sev, grp, True) for n, rx, sev, grp in self.extra_secrets]
            for name, rx, sev, grp, is_custom in builtin + custom:
                for m in rx.finditer(text):
                    try:
                        val = m.group(grp) if grp else m.group(0)
                    except (IndexError, re.error):
                        val = m.group(0)
                    if not val:
                        continue
                    note, s = "", sev
                    # Built-in patterns demote obvious placeholders; user-supplied
                    # rules are trusted to carry their own severity.
                    if not is_custom and any(ph in val.lower()
                                             for ph in P.SECRET_PLACEHOLDERS):
                        note = "likely placeholder/example — verify"
                        s = P.SEV_LOW
                    emit(CAT_SECRETS, name, val, s, m.start(grp if grp else 0), note)

            # generic high-entropy strings (catch-all for unknown key formats)
            if self.verify_entropy:
                for m in re.finditer(r"""['"]([A-Za-z0-9+/_\-]{20,120})['"]""", text):
                    cand = m.group(1)
                    if any(ph in cand.lower() for ph in P.SECRET_PLACEHOLDERS):
                        continue
                    ent = shannon_entropy(cand)
                    if ent >= self.ENTROPY_THRESHOLD and _looks_random(cand):
                        emit(CAT_SECRETS, "High-entropy string",
                             cand, P.SEV_LOW, m.start(1),
                             f"entropy={ent:.2f} — possible secret, verify")

        # -- links / dirs / params ------------------------------------------
        link_hits = []
        if self.want(CAT_LINKS) or self.want(CAT_DIRS) or self.want(CAT_PARAMS):
            for m in P.LINK_REGEX.finditer(text):
                raw = m.group(1)
                if _is_secretish_token(raw):
                    continue  # base64/secret blob that merely looks path-like
                link_hits.append((raw, m.start(1)))

        if self.want(CAT_LINKS):
            for raw, pos in link_hits:
                emit(CAT_LINKS, _classify_link(raw), raw, P.SEV_INFO, pos)

        if self.want(CAT_DIRS):
            seen_dirs = set()
            for raw, pos in link_hits:
                for d in _directories_of(raw):
                    if d not in seen_dirs:
                        seen_dirs.add(d)
                        emit(CAT_DIRS, "directory", d, P.SEV_INFO, pos)

        if self.want(CAT_PARAMS):
            for raw, pos in link_hits:
                for pm in P.PARAM_REGEX.finditer(raw):
                    emit(CAT_PARAMS, "param", pm.group(1), P.SEV_INFO, pos)

        # -- domains ---------------------------------------------------------
        if self.want(CAT_DOMAINS):
            for m in P.DOMAIN_REGEX.finditer(text):
                emit(CAT_DOMAINS, "domain", m.group(1), P.SEV_INFO, m.start(1))

        # -- IPs -------------------------------------------------------------
        if self.want(CAT_IPS):
            for m in P.IP_REGEX.finditer(text):
                ip = m.group(1)
                port = m.group(2)
                val = f"{ip}:{port}" if port else ip
                note, sev = "", P.SEV_INFO
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        note, sev = "RFC1918 private — internal infra leak", P.SEV_LOW
                    elif ip_obj.is_loopback:
                        note = "loopback"
                except ValueError:
                    continue
                emit(CAT_IPS, "ipv4", val, sev, m.start(1), note)

        # -- emails ----------------------------------------------------------
        if self.want(CAT_EMAILS):
            for m in P.EMAIL_REGEX.finditer(text):
                emit(CAT_EMAILS, "email", m.group(0), P.SEV_INFO, m.start())

        # -- S3 --------------------------------------------------------------
        if self.want(CAT_S3):
            for m in P.S3_REGEX.finditer(text):
                emit(CAT_S3, "s3-bucket", m.group(0), P.SEV_MEDIUM, m.start(),
                     "check for public listing / takeover")

        # -- DOM-XSS ---------------------------------------------------------
        # Only report a sink when at least one taint SOURCE is present in the
        # same file: a lone sink (no attacker-controllable input) or a lone
        # source (no dangerous operation) is not exploitable, so we stay quiet.
        # One finding per distinct sink type, naming the sources to trace.
        if self.want(CAT_DOM):
            sources_present = [name for name, rx in P.DOM_SOURCES if rx.search(text)]
            if sources_present:
                src_list = ", ".join(sources_present[:6])
                seen_sinks = set()
                for name, rx, sev in P.DOM_SINKS:
                    m = rx.search(text)
                    if not m or name in seen_sinks:
                        continue
                    seen_sinks.add(name)
                    # Co-occurrence is a strong lead, not proof of data flow, so
                    # cap the rating at HIGH rather than claiming CRITICAL.
                    if sev == P.SEV_CRITICAL:
                        sev = P.SEV_HIGH
                    emit(CAT_DOM, "Potential DOM XSS", name, sev, m.start(),
                         f"sink reachable if fed by a source in this file "
                         f"(sources present: {src_list}) — verify data flow")

        # -- other vulns -----------------------------------------------------
        if self.want(CAT_VULNS):
            for name, rx, sev, advice in P.VULN_PATTERNS:
                m = rx.search(text)            # one finding per vuln type per file
                if m:
                    emit(CAT_VULNS, name, advice, sev, m.start())

            # Cleartext HTTP — only if it points at the target scope.
            if self.target_domains:
                seen_http = set()
                for m in P.INSECURE_HTTP_REGEX.finditer(text):
                    url = m.group(1)
                    try:
                        host = urlparse(url).hostname
                    except ValueError:
                        continue
                    if host and self._in_scope(host) and url not in seen_http:
                        seen_http.add(url)
                        emit(CAT_VULNS, "Insecure HTTP endpoint (in scope)", url,
                             P.SEV_LOW, m.start(1),
                             "cleartext HTTP to target — MITM / mixed-content risk")

        # -- comments --------------------------------------------------------
        if self.want(CAT_COMMENTS):
            for ctext, cpos in iter_comments(text):
                if P.COMMENT_KEYWORDS.search(ctext):
                    snippet = re.sub(r"\s+", " ", ctext).strip()
                    if len(snippet) > 200:
                        snippet = snippet[:200] + "…"
                    emit(CAT_COMMENTS, "comment", snippet, P.SEV_INFO, cpos)

        return _dedupe(findings)


def _looks_random(s):
    """Heuristic: reject obvious non-secrets (words, base64 of ascii text)."""
    if " " in s:
        return False
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    # mixed char classes are more secret-like
    return has_digit and has_alpha


def _is_secretish_token(raw):
    """True for strings that match the link regex but are really key/base64 blobs.

    Guards against e.g. an AWS secret 'wJalr.../K7.../bP...' being reported as an
    endpoint + directory tree. Only fires for scheme-less, dot-less, root-less
    tokens whose character distribution looks random.
    """
    if raw.startswith(("/", "./", "../", "//")):
        return False
    if re.match(r"^[a-zA-Z]{1,10}://", raw):
        return False
    if "." in raw or "?" in raw or "#" in raw:
        return False
    core = raw.replace("/", "")
    if len(core) < 16:
        return False
    return shannon_entropy(core) >= 4.2 and _looks_random(core)


def _classify_link(raw):
    if raw.startswith("//") or re.match(r"^[a-zA-Z]{1,10}://", raw):
        return "absolute-url"
    if raw.startswith("/"):
        return "root-relative"
    if raw.startswith("./") or raw.startswith("../"):
        return "relative"
    return "endpoint"


def _directories_of(raw):
    """Yield directory prefixes implied by a link/endpoint."""
    path = raw
    if "://" in raw:
        try:
            path = urlparse(raw).path
        except ValueError:
            return
    elif raw.startswith("//"):
        try:
            path = urlparse("http:" + raw).path
        except ValueError:
            return
    path = path.split("?", 1)[0].split("#", 1)[0]
    if not path or path in ("/",):
        return
    parts = [p for p in path.split("/") if p not in ("", ".", "..")]
    # drop a trailing filename (has a dot and an extension-ish tail)
    if parts and re.search(r"\.[a-zA-Z0-9]{1,6}$", parts[-1]):
        parts = parts[:-1]
    acc = ""
    for p in parts:
        acc += "/" + p
        yield acc


def _dedupe(findings):
    seen = {}
    for f in findings:
        k = f.key()
        if k not in seen:
            seen[k] = f
        else:
            # keep the higher severity instance
            if P.SEVERITY_ORDER[f.severity] < P.SEVERITY_ORDER[seen[k].severity]:
                seen[k] = f
    out = list(seen.values())
    out.sort(key=lambda f: (P.SEVERITY_ORDER[f.severity], f.category, f.kind, f.value))
    return out
