"""Output renderers: txt, json, csv, html."""

import csv
import html as _html
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xesc, quoteattr as _xattr

from . import hints
from . import patterns as P
from .extractor import ALL_CATEGORIES, CATEGORY_TITLES


def _sources_str(f, limit=4):
    """Compact 'where it was found' string from an aggregated finding."""
    srcs = getattr(f, "sources", None)
    if not srcs:
        return ""
    shown = srcs[:limit]
    extra = len(srcs) - len(shown)
    s = ", ".join(shown)
    return s + (f" (+{extra} more)" if extra > 0 else "")

SEV_COLORS = {
    P.SEV_CRITICAL: "#e5484d",
    P.SEV_HIGH: "#f76808",
    P.SEV_MEDIUM: "#ffb224",
    P.SEV_LOW: "#3e9b4f",
    P.SEV_INFO: "#6e7781",
}

# ANSI for terminal txt output when writing to stdout/tty.
ANSI = {
    P.SEV_CRITICAL: "\033[1;91m",
    P.SEV_HIGH: "\033[1;31m",
    P.SEV_MEDIUM: "\033[1;33m",
    P.SEV_LOW: "\033[1;32m",
    P.SEV_INFO: "\033[0;37m",
}
ANSI_RESET = "\033[0m"
ANSI_DIM = "\033[2m"
ANSI_BOLD = "\033[1m"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _group(findings):
    """Return {category: [findings]} preserving ALL_CATEGORIES order."""
    g = {c: [] for c in ALL_CATEGORIES}
    for f in findings:
        g.setdefault(f.category, []).append(f)
    return {c: v for c, v in g.items() if v}


def summarise(results):
    """results: list of (origin, findings). Returns counts dict."""
    by_sev = {s: 0 for s in P.SEVERITY_ORDER}
    by_cat = {}
    total = 0
    for _, findings in results:
        for f in findings:
            total += 1
            by_sev[f.severity] += 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {"total": total, "by_severity": by_sev, "by_category": by_cat}


# ---------------------------------------------------------------------------
# TXT
# ---------------------------------------------------------------------------
def render_txt(results, meta, color=False):
    out = io.StringIO()
    summary_only = meta.get("summary_only")
    cap = meta.get("max_per_category") or 0   # 0 = unlimited

    def c(sev, s):
        return f"{ANSI.get(sev,'')}{s}{ANSI_RESET}" if color else s

    def dim(s):
        return f"{ANSI_DIM}{s}{ANSI_RESET}" if color else s

    bold = (lambda s: f"{ANSI_BOLD}{s}{ANSI_RESET}") if color else (lambda s: s)

    out.write(bold(f"jsrecon report  —  {meta['generated']}\n"))
    out.write(f"sources: {meta['source_count']}   "
              f"total findings: {meta['summary']['total']}\n")
    # Severity tally — excluding INFO (inventory, not issues).
    sev = meta["summary"]["by_severity"]
    sev_parts = [c(s, f"{s}={sev[s]}") for s in P.SEVERITY_ORDER
                 if s != P.SEV_INFO and sev[s]]
    if sev_parts:
        out.write("severity: " + "  ".join(sev_parts) + "\n")
    # Per-category breakdown — a quick map of where the findings are.
    cats = meta["summary"]["by_category"]
    out.write("category: " + "  ".join(
        f"{ct}={n}" for ct, n in sorted(cats.items(), key=lambda kv: -kv[1])) + "\n")
    if summary_only:
        out.write(dim("(summary: showing critical+high only — "
                      "drop --summary or use -f json for everything)\n"))
    out.write("=" * 78 + "\n")

    show_files = meta.get("source_count", 1) > 1
    verbose = meta.get("verbose")

    def emit_finding(f):
        tag = c(f.severity, f"[{f.severity.upper()}]")
        mult = dim(f" x{f.count}") if getattr(f, "count", 1) > 1 else ""
        out.write(f"    {tag} {f.kind}: {f.value}{mult}\n")
        if f.note:
            out.write(dim(f"           - {f.note}\n"))
        tip = hints.hint(f)
        if tip:
            out.write(dim(f"           - exploit: {tip}\n"))
        # Show affected files for real issues (and sensitive secrets); the full
        # INFO inventory is included only in --verbose mode.
        if show_files and (verbose or f.severity != P.SEV_INFO
                           or f.category == "secrets"):
            srcs = _sources_str(f)
            if srcs:
                out.write(dim(f"           - files: {srcs}\n"))

    for origin, findings in results:
        if summary_only:
            findings = [f for f in findings
                        if P.SEVERITY_ORDER[f.severity] <= P.SEVERITY_ORDER[P.SEV_HIGH]]
        if not findings:
            continue
        out.write("\n" + bold(f"### {origin}") + f"   ({len(findings)} findings)\n")
        for cat, items in _group(findings).items():
            shown = items if cap <= 0 else items[:cap]
            more = len(items) - len(shown)
            out.write("\n  " + bold(CATEGORY_TITLES.get(cat, cat)) +
                      f"  [{len(items)}]\n")
            for f in shown:
                emit_finding(f)
            if more > 0:
                out.write(dim(f"    … and {more} more "
                              f"(raise --max-per-category or use -f json)\n"))
    out.write("\n")
    return out.getvalue()


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def _finding_dict(f):
    d = f.to_dict()
    tip = hints.hint(f)
    if tip:
        d["exploit"] = tip
    return d


def render_json(results, meta):
    doc = {
        "tool": "jsrecon",
        "version": meta.get("version"),
        "generated": meta["generated"],
        "summary": meta["summary"],
        "sources": [
            {
                "origin": origin,
                "findings": [_finding_dict(f) for f in findings],
            }
            for origin, findings in results
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def render_csv(results, meta):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["files", "category", "kind", "severity", "line", "count",
                "value", "note", "exploit"])
    for origin, findings in results:
        for f in findings:
            files = "; ".join(getattr(f, "sources", None) or [origin])
            w.writerow([files, f.category, f.kind, f.severity, f.line,
                        getattr(f, "count", 1), f.value, f.note, hints.hint(f)])
    return out.getvalue()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def render_html(results, meta):
    e = _html.escape
    sev = meta["summary"]["by_severity"]
    cats = meta["summary"]["by_category"]

    sev_chips = "".join(
        f'<span class="chip" style="--c:{SEV_COLORS[s]}">{s}: {sev[s]}</span>'
        for s in P.SEVERITY_ORDER if sev[s]
    )
    cat_chips = "".join(
        f'<span class="chip chip-cat">{e(CATEGORY_TITLES.get(c,c))}: {n}</span>'
        for c, n in sorted(cats.items(), key=lambda kv: -kv[1])
    )

    summary_only = meta.get("summary_only")
    cap = meta.get("max_per_category") or 0

    sections = []
    for origin, findings in results:
        if summary_only:
            findings = [f for f in findings
                        if P.SEVERITY_ORDER[f.severity] <= P.SEVERITY_ORDER[P.SEV_HIGH]]
        if not findings:
            continue
        groups = _group(findings)
        blocks = []
        for cat, items in groups.items():
            shown = items if cap <= 0 else items[:cap]
            more = len(items) - len(shown)
            rows = []
            for f in shown:
                mult = (f'<span class="mult">×{f.count}</span>'
                        if getattr(f, "count", 1) > 1 else "")
                tip = hints.hint(f)
                tip_html = f'<div class="tip"><b>exploit:</b> {e(tip)}</div>' if tip else ""
                show_src = (meta.get("source_count", 1) > 1
                            and (meta.get("verbose") or f.severity != P.SEV_INFO
                                 or f.category == "secrets"))
                srcs = _sources_str(f) if show_src else ""
                src_html = f'<div class="src"><b>files:</b> {e(srcs)}</div>' if srcs else ""
                note_html = f'<div>{e(f.note)}</div>' if f.note else ""
                rows.append(f"""
                <tr data-sev="{e(f.severity)}" data-cat="{e(f.category)}">
                  <td><span class="sev" style="--c:{SEV_COLORS[f.severity]}">{e(f.severity)}</span></td>
                  <td class="kind">{e(f.kind)}</td>
                  <td class="val"><code>{e(f.value)}</code>{mult}</td>
                  <td class="note">{note_html}{tip_html}{src_html}</td>
                </tr>""")
            more_row = (f'<tr class="more"><td colspan="4">… and {more} more '
                        f'(raise --max-per-category or use -f json)</td></tr>'
                        if more > 0 else "")
            blocks.append(f"""
            <details class="cat" open>
              <summary>{e(CATEGORY_TITLES.get(cat, cat))} <span class="count">{len(items)}</span></summary>
              <table>
                <thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Detail</th></tr></thead>
                <tbody>{''.join(rows)}{more_row}</tbody>
              </table>
            </details>""")
        sections.append(f"""
        <section class="source">
          <h2 title="{e(origin)}">{e(origin)} <span class="count">{len(findings)}</span></h2>
          {''.join(blocks)}
        </section>""")

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jsrecon report</title>
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
    --muted:#8b949e; --accent:#58a6ff;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg:#f6f8fa; --panel:#fff; --border:#d0d7de; --fg:#1f2328; --muted:#636c76; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
         background:var(--bg); color:var(--fg); }}
  header {{ padding:20px 24px; border-bottom:1px solid var(--border); background:var(--panel);
           position:sticky; top:0; z-index:10; }}
  h1 {{ margin:0 0 4px; font-size:20px; }}
  h1 small {{ color:var(--muted); font-weight:400; font-size:13px; }}
  .meta {{ color:var(--muted); margin-bottom:12px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }}
  .chip {{ padding:2px 10px; border-radius:999px; border:1px solid var(--c,var(--border));
          color:var(--c,var(--fg)); font-size:12px; }}
  .chip-cat {{ --c:var(--muted); }}
  .controls {{ margin-top:12px; display:flex; gap:12px; flex-wrap:wrap; align-items:center; }}
  .controls input {{ background:var(--bg); border:1px solid var(--border); color:var(--fg);
                    padding:6px 10px; border-radius:6px; min-width:220px; }}
  .controls label {{ color:var(--muted); font-size:12px; cursor:pointer; }}
  main {{ padding:24px; max-width:1100px; margin:0 auto; }}
  section.source {{ margin-bottom:28px; }}
  section.source > h2 {{ font-size:15px; word-break:break-all; border-bottom:1px solid var(--border);
                        padding-bottom:6px; }}
  details.cat {{ margin:10px 0; border:1px solid var(--border); border-radius:8px;
                background:var(--panel); overflow:hidden; }}
  summary {{ cursor:pointer; padding:10px 14px; font-weight:600; }}
  .count {{ display:inline-block; background:var(--border); color:var(--fg); border-radius:999px;
           padding:0 8px; font-size:12px; margin-left:6px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th,td {{ text-align:left; padding:6px 14px; border-top:1px solid var(--border);
          vertical-align:top; }}
  th {{ color:var(--muted); font-weight:500; font-size:12px; }}
  td.val code {{ word-break:break-all; color:var(--accent); }}
  td.note {{ color:var(--muted); font-size:12px; }}
  .sev {{ color:var(--c); border:1px solid var(--c); border-radius:4px; padding:0 6px;
         font-size:11px; text-transform:uppercase; }}
  tr.hidden {{ display:none; }}
  tr.more td {{ color:var(--muted); font-style:italic; }}
  .mult {{ color:var(--muted); font-size:11px; margin-left:6px; }}
  td.note div {{ margin:1px 0; }}
  td.note .tip {{ color:var(--accent); }}
  td.note .src {{ color:var(--muted); word-break:break-all; }}
  td.note b {{ font-weight:600; }}
</style></head><body>
<header>
  <h1>jsrecon report <small>v{e(str(meta.get('version','')))}</small></h1>
  <div class="meta">Generated {e(meta['generated'])} · {meta['source_count']} source(s) · {meta['summary']['total']} findings</div>
  <div class="chips">{sev_chips}</div>
  <div class="chips">{cat_chips}</div>
  <div class="controls">
    <input id="q" type="search" placeholder="filter by text…" oninput="filt()">
    <label><input type="checkbox" class="sf" value="critical" checked onchange="filt()"> critical</label>
    <label><input type="checkbox" class="sf" value="high" checked onchange="filt()"> high</label>
    <label><input type="checkbox" class="sf" value="medium" checked onchange="filt()"> medium</label>
    <label><input type="checkbox" class="sf" value="low" checked onchange="filt()"> low</label>
    <label><input type="checkbox" class="sf" value="info" checked onchange="filt()"> info</label>
  </div>
</header>
<main>{''.join(sections) or '<p>No findings.</p>'}</main>
<script>
function filt() {{
  var q = document.getElementById('q').value.toLowerCase();
  var sevs = {{}};
  document.querySelectorAll('.sf').forEach(function(c){{ sevs[c.value]=c.checked; }});
  document.querySelectorAll('tbody tr').forEach(function(tr){{
    var okSev = sevs[tr.getAttribute('data-sev')] !== false;
    var okTxt = tr.textContent.toLowerCase().indexOf(q) !== -1;
    tr.classList.toggle('hidden', !(okSev && okTxt));
  }});
}}
</script>
</body></html>"""


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------
def render_xml(results, meta):
    s = meta["summary"]
    out = ['<?xml version="1.0" encoding="UTF-8"?>']
    out.append(f'<jsrecon version={_xattr(str(meta.get("version","")))} '
               f'generated={_xattr(meta["generated"])}>')
    out.append(f'  <summary sources="{meta["source_count"]}" '
               f'findings="{s["total"]}">')
    for sev, n in s["by_severity"].items():
        if n:
            out.append(f'    <severity level={_xattr(sev)} count="{n}"/>')
    for cat, n in s["by_category"].items():
        out.append(f'    <category name={_xattr(cat)} count="{n}"/>')
    out.append('  </summary>')
    out.append('  <findings>')
    for origin, findings in results:
        for f in findings:
            tip = hints.hint(f)
            out.append(f'    <finding category={_xattr(f.category)} '
                       f'severity={_xattr(f.severity)} count="{getattr(f,"count",1)}" '
                       f'line="{f.line or 0}">')
            out.append(f'      <type>{_xesc(f.kind)}</type>')
            out.append(f'      <value>{_xesc(f.value)}</value>')
            if f.note:
                out.append(f'      <note>{_xesc(f.note)}</note>')
            if tip:
                out.append(f'      <exploit>{_xesc(tip)}</exploit>')
            srcs = getattr(f, "sources", None) or ([origin] if origin else [])
            if srcs:
                out.append('      <files>')
                for src in srcs:
                    out.append(f'        <file>{_xesc(src)}</file>')
                out.append('      </files>')
            out.append('    </finding>')
    out.append('  </findings>')
    out.append('</jsrecon>')
    return "\n".join(out) + "\n"


RENDERERS = {
    "txt": render_txt,
    "json": render_json,
    "csv": render_csv,
    "html": render_html,
    "xml": render_xml,
}
