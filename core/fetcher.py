"""Input acquisition: local files, remote URLs, and URL lists.

Uses `requests` if installed, otherwise falls back to urllib from the stdlib.
Only http/https and local paths are accepted. Remote content is treated as
untrusted data: it is only ever read as text and scanned with regexes — never
executed, imported, or interpreted.
"""

import concurrent.futures
import os
import random
import ssl
import time
import urllib.error
import urllib.request

try:
    import requests  # type: ignore
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

# Clean, current browser UA — no tool identifier (that would defeat stealth).
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Pool of realistic UAs rotated in --stealth mode.
STEALTH_UAS = [
    DEFAULT_UA,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

DEFAULT_TIMEOUT = 20
MAX_BYTES = 25 * 1024 * 1024  # 25 MB cap per resource


def _stealth_headers(referer):
    """Browser-like headers that make a fetch blend in with normal traffic."""
    same_site = bool(referer)
    return {
        "User-Agent": random.choice(STEALTH_UAS),
        "Accept": "*/*",
        "Accept-Language": random.choice(
            ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.8,fr;q=0.5"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "script" if same_site else "document",
        "Sec-Fetch-Mode": "no-cors" if same_site else "navigate",
        "Sec-Fetch-Site": "same-origin" if same_site else "none",
        "Connection": "keep-alive",
    }


class Source:
    """A single unit of JS to analyse."""

    def __init__(self, origin, content, error=None):
        self.origin = origin          # file path or URL
        self.content = content or ""
        self.error = error            # str if fetch failed
        self.size = len(self.content)

    @property
    def ok(self):
        return self.error is None and bool(self.content)


def is_url(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def read_local(path: str) -> Source:
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            return Source(path, None, f"file too large ({size} bytes, cap {MAX_BYTES})")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return Source(path, fh.read())
    except OSError as e:
        return Source(path, None, f"read error: {e}")


def fetch_url(url, timeout=DEFAULT_TIMEOUT, headers=None, proxy=None,
              insecure=False, cookie=None, stealth=False, referer=None,
              delay=0.0, jitter=0.0) -> Source:
    # Throttle: a base delay plus random jitter spreads requests out so a crawl
    # does not arrive as an obvious burst.
    if delay or jitter:
        time.sleep(max(0.0, delay) + (random.uniform(0, jitter) if jitter else 0))

    if stealth:
        hdrs = _stealth_headers(referer)
    else:
        hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if referer:
        hdrs["Referer"] = referer
    if headers:
        hdrs.update(headers)          # user -H overrides everything
    if cookie:
        hdrs["Cookie"] = cookie

    if _HAVE_REQUESTS:
        try:
            proxies = {"http": proxy, "https": proxy} if proxy else None
            resp = requests.get(
                url, headers=hdrs, timeout=timeout, proxies=proxies,
                verify=not insecure, stream=True, allow_redirects=True,
            )
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=65536, decode_unicode=False):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_BYTES:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            if resp.status_code >= 400:
                return Source(url, text, f"HTTP {resp.status_code}")
            return Source(url, text)
        except Exception as e:
            return Source(url, None, f"fetch error: {e}")

    # stdlib fallback
    try:
        ctx = None
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if proxy:
            handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener = urllib.request.build_opener(handler)
            urllib.request.install_opener(opener)
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(MAX_BYTES)
            charset = r.headers.get_content_charset() or "utf-8"
            return Source(url, raw.decode(charset, errors="replace"))
    except urllib.error.HTTPError as e:
        return Source(url, None, f"HTTP {e.code}")
    except Exception as e:
        return Source(url, None, f"fetch error: {e}")


def load_targets(targets, list_file=None, threads=5, **fetch_kw):
    """Resolve a mix of file paths / URLs / a list-file into Source objects."""
    items = list(targets or [])
    if list_file:
        with open(list_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)

    # de-duplicate, keep order
    seen, ordered = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            ordered.append(it)

    urls = [t for t in ordered if is_url(t)]
    files = [t for t in ordered if not is_url(t)]

    sources = {}
    # local files (fast, sequential)
    for f in files:
        sources[f] = read_local(f)

    # remote URLs (threaded)
    if urls:
        workers = max(1, min(threads, len(urls)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            fut = {ex.submit(fetch_url, u, **fetch_kw): u for u in urls}
            for f in concurrent.futures.as_completed(fut):
                u = fut[f]
                try:
                    sources[u] = f.result()
                except Exception as e:
                    sources[u] = Source(u, None, f"worker error: {e}")

    # return in original order
    return [sources[t] for t in ordered]


def read_stdin() -> Source:
    import sys
    data = sys.stdin.read()
    return Source("<stdin>", data)
