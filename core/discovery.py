"""Discovery & source-map recovery.

Two related jobs:

1. Crawl an HTML page and enumerate the JavaScript it loads (``<script src>``,
   module/preload hints, and any ``.js`` URL referenced in the markup), plus
   inline scripts, flagging security-interesting filenames.

2. Source-map recovery: locate a JS file's ``sourceMappingURL`` (external or
   inline ``data:`` URI), fetch/decode the ``.map`` JSON, and recover the
   original ``sourcesContent`` so pre-minification code can be scanned too.

Everything here only reads/parses text. Fetched maps are JSON-parsed, never
executed.
"""

import base64
import json
import re
from urllib.parse import urljoin, urlparse

# --- regexes --------------------------------------------------------------
_SCRIPT_SRC = re.compile(
    r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_INLINE_SCRIPT = re.compile(
    r"""<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>""",
    re.IGNORECASE | re.DOTALL)
_LINK_SCRIPT = re.compile(
    r"""<link\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>""", re.IGNORECASE)
_ANY_JS_URL = re.compile(
    r"""["'`]([^"'`\s]+?\.js(?:\?[^"'`\s]*)?)["'`]""", re.IGNORECASE)
_DYNAMIC_IMPORT = re.compile(
    r"""\bimport\s*\(\s*["'`]([^"'`]+?\.js(?:\?[^"'`]*)?)["'`]""", re.IGNORECASE)
_IMPORT_SCRIPTS = re.compile(
    r"""\bimportScripts\s*\(\s*["'`]([^"'`]+?)["'`]""", re.IGNORECASE)
# webpack publicPath assignment: __webpack_require__.p = "…"
_PUBLIC_PATH = re.compile(r"""\.p\s*=\s*["']([^"']*)["']""")
# webpack chunk-filename function head:  .u = function(e){return …  |  .u = e =>  …
_CHUNK_FN = re.compile(
    r"""\.u\s*=\s*(?:function\s*\([^)]*\)\s*\{\s*return|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)""")
# // # sourceMappingURL=... or /*# sourceMappingURL=... */
_SOURCEMAP = re.compile(
    r"""(?:/[/*][#@]\s*sourceMappingURL=)\s*([^\s'"*]+)""", re.IGNORECASE)

# Filename hints that make a JS file worth prioritising.
_HINTS_HIGH = (
    "config", "conf", "env", "settings", "setting", "secret", "credential",
    "admin", "auth", "login", "token", "oauth", "firebase", "internal",
    "private", "backend", "payment", "account", "apikey", "api-key",
)
_HINTS_MED = (
    "api", "graphql", "main", "app", "bundle", "index", "vendor", "runtime",
    "manifest", "webpack", "chunk", "polyfill", "common", "core",
)


def _is_html(text):
    head = text[:4096].lower()
    return ("<html" in head or "<!doctype html" in head
            or ("<script" in head and "<" in head and ">" in head))


def looks_like_html(source_text):
    return _is_html(source_text)


def importance(url):
    """Return (severity, reason) for a discovered JS URL based on its name."""
    name = urlparse(url).path.lower()
    for h in _HINTS_HIGH:
        if h in name:
            return "high", f"name hints sensitive content ('{h}')"
    for h in _HINTS_MED:
        if h in name:
            return "medium", f"likely application code ('{h}')"
    return "info", ""


def find_js_links(html, base_url):
    """Return an ordered, de-duplicated list of absolute JS URLs in *html*."""
    found = []
    seen = set()

    def add(u):
        if not u:
            return
        u = u.strip()
        if u.startswith(("data:", "javascript:", "#")):
            return
        absu = urljoin(base_url or "", u)
        if absu not in seen:
            seen.add(absu)
            found.append(absu)

    for m in _SCRIPT_SRC.finditer(html):
        add(m.group(1))
    # <link rel=preload/modulepreload as=script href=...>
    for m in _LINK_SCRIPT.finditer(html):
        tag = m.group(0).lower()
        if "script" in tag or "modulepreload" in tag or ".js" in m.group(1).lower():
            add(m.group(1))
    # any other .js reference in the markup (webpack manifests, lazy chunks)
    for m in _ANY_JS_URL.finditer(html):
        add(m.group(1))
    return found


def find_js_refs_in_js(js_text, base_url):
    """Return JS URLs referenced *inside a JS file* (for recursive discovery).

    Covers plain ``"…​.js"`` string references, dynamic ``import("…")`` and
    ``importScripts("…")``, plus reconstructed webpack chunk URLs. All resolved
    to absolute URLs against *base_url*.
    """
    found, seen = [], set()

    def add(u):
        if not u:
            return
        u = u.strip()
        if u.startswith(("data:", "javascript:", "#")):
            return
        # Skip bare template fragments like ".chunk.js" / ".js" whose final path
        # segment begins with a dot (not a real relative "./" or "../" ref).
        seg = u.split("?", 1)[0].split("/")[-1]
        if seg.startswith(".") and not u.startswith(("./", "../")):
            return
        absu = urljoin(base_url or "", u)
        if absu not in seen:
            seen.add(absu)
            found.append(absu)

    for rx in (_ANY_JS_URL, _DYNAMIC_IMPORT, _IMPORT_SCRIPTS):
        for m in rx.finditer(js_text):
            add(m.group(1))
    for u in webpack_chunks(js_text, base_url):
        add(u)
    return found


def webpack_chunks(js_text, base_url):
    """Best-effort reconstruction of webpack lazy-chunk URLs.

    Webpack emits a chunk-filename function (``__webpack_require__.u``) of the
    shape ``prefix + id + "." + {id:hash}[id] + ".chunk.js"`` (optionally with a
    ``{id:name}[id]||id`` name map). This parses that function plus the chunk
    hash/name maps and the ``publicPath`` to rebuild each chunk's URL. It is a
    heuristic: unrecognised runtimes yield nothing, and bad guesses simply 404
    and are skipped by the fetcher.
    """
    public_path = ""
    m = _PUBLIC_PATH.search(js_text)
    if m:
        public_path = m.group(1)

    results, seen = [], set()
    for fn in _CHUNK_FN.finditer(js_text):
        # Grab a generous window; the real end is found after maps are removed
        # (map objects contain '}' that would otherwise cut the expression short).
        window = js_text[fn.end():fn.end() + 800]
        try:
            for url in _reconstruct_chunks(window, public_path, base_url):
                if url not in seen:
                    seen.add(url)
                    results.append(url)
        except Exception:
            continue
    return results


def _reconstruct_chunks(expr, public_path, base_url):
    # Pull out the inline {id:"val", …} maps, replacing each with a marker.
    maps = []

    def grab_map(mo):
        body = mo.group(1)
        d = {}
        for km in re.finditer(r"""(?:(\d+)|["']([^"']+)["'])\s*:\s*["']([^"']*)["']""", body):
            key = km.group(1) if km.group(1) is not None else km.group(2)
            d[key] = km.group(3)
        maps.append(d)
        return f"\x00{len(maps) - 1}\x00"

    cleaned = re.sub(r"\{([^{}]*)\}", grab_map, expr)
    if not maps:
        return []
    # Now that map braces are gone, the first ';' or '}' is the real expr end.
    end = re.search(r"[;}]", cleaned)
    if end:
        cleaned = cleaned[:end.start()]

    tokens = [t.strip() for t in cleaned.split("+") if t.strip()]

    ids = set()
    for d in maps:
        ids.update(d.keys())
    if not ids:
        return []

    out = []
    for cid in ids:
        pieces, ok = [], True
        for tok in tokens:
            if re.fullmatch(r"""["'][^"']*["']""", tok):
                pieces.append(tok[1:-1])
            elif "\x00" in tok:
                mi = int(re.search(r"\x00(\d+)\x00", tok).group(1))
                d = maps[mi]
                # "(map[e]||e)" => name lookup with id fallback; "map[e]" => hash
                pieces.append(d.get(cid, cid) if "||" in tok else d.get(cid, ""))
            elif re.fullmatch(r"[A-Za-z_$][\w$]*", tok):
                pieces.append(str(cid))           # the chunk-id variable
            else:
                ok = False
                break
        name = "".join(pieces)
        if ok and name.endswith(".js"):
            out.append(urljoin(base_url or "", public_path + name))
    return out


def find_inline_scripts(html):
    """Return inline <script> bodies (those without a src attribute)."""
    bodies = []
    for m in _INLINE_SCRIPT.finditer(html):
        body = m.group(1).strip()
        if body:
            bodies.append(body)
    return bodies


def find_sourcemap_url(js_text):
    """Return the raw sourceMappingURL token from *js_text*, or None.

    Uses the last occurrence (that is the one the browser honours).
    """
    matches = _SOURCEMAP.findall(js_text)
    return matches[-1].strip() if matches else None


def resolve_sourcemap(raw, js_url):
    """Resolve a raw sourceMappingURL to either ('inline', json_text) or
    ('url', absolute_url)."""
    if raw.startswith("data:"):
        # data:application/json;base64,XXXX  or  data:application/json,{...}
        header, _, payload = raw.partition(",")
        if "base64" in header:
            try:
                return "inline", base64.b64decode(payload).decode("utf-8", "replace")
            except Exception:
                return None, None
        from urllib.parse import unquote
        return "inline", unquote(payload)
    return "url", urljoin(js_url or "", raw)


def recover_sources(map_text, map_origin):
    """Parse a source-map document and return [(name, content), ...].

    Handles the optional ``)]}'`` XSSI guard prefix some tools emit.
    """
    text = map_text.lstrip()
    if text.startswith(")]}"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    try:
        data = json.loads(text)
    except Exception:
        return []

    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    root = data.get("sourceRoot") or ""
    out = []
    for i, content in enumerate(contents):
        if not content:
            continue
        name = sources[i] if i < len(sources) else f"source_{i}"
        if root and not name.startswith(("http://", "https://", "/")):
            name = root.rstrip("/") + "/" + name.lstrip("/")
        # tidy webpack-style names: webpack://app/./src/foo.js
        name = re.sub(r"^webpack://[^/]*/", "", name)
        label = f"{map_origin} → {name}"
        out.append((label, content))
    return out
