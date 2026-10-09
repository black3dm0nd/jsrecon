<h1 align="center">jsrecon</h1>

<p align="center">
  <b>Client-side attack-surface mapper for web pentests and bug bounty.</b><br>
  <i>by black3dm0nd</i>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-blue">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none-brightgreen">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

```text
     _
    (_)___ _ __ ___  ___ ___  _ __
    | / __| '__/ _ \/ __/ _ \| '_ \
    | \__ \ | |  __/ (_| (_) | | | |
   _/ |___/_|  \___|\___\___/|_| |_|
  |__/   JavaScript recon & secret miner  v1.0.0
                                by black3dm0nd
```

`jsrecon` scans JavaScript from local files, URLs, URL lists, stdin, or a crawled
site and extracts the client-side signals that matter during authorized security
testing: hard-coded secrets, endpoints, parameters, directories, domains, IPs,
S3 buckets, source maps, high-signal DOM-XSS leads, concrete client-side
misconfigurations, and revealing developer comments.

It beautifies JavaScript before scanning, aggregates and de-duplicates findings
across every source by default, tags findings with the source file when useful,
adds one-line exploitation hints, and exports to text, HTML, JSON, CSV, or XML.

## Authorized Use Only

Use `jsrecon` only on assets you own or have explicit permission to test, such as
a signed engagement or an in-scope bug bounty target. Fetching third-party
JavaScript and acting on discovered secrets or endpoints without authorization
may be illegal. For discovered secrets, prefer read-only validation over any
state-changing request.

The bundled [examples/sample.js](examples/sample.js) file contains fake
credentials for testing.

## Highlights

- Zero required third-party dependencies; optional `requests` and `jsbeautifier`
  improve fetching and beautification.
- Local file, URL, URL list, stdin, recursive crawl, and extract-only workflows.
- Recursive discovery for script tags, inline scripts, dynamic imports,
  `importScripts()`, generic `.js` references, and webpack lazy chunks.
- Source-map recovery for external and inline `sourceMappingURL` values.
- Built-in secret patterns for cloud, SaaS, payment, CI, messaging, database,
  authorization, private-key, JWT, and generic credential formats.
- DOM-XSS triage that requires a source and sink in the same file to reduce
  noise.
- Scope-aware cleartext HTTP detection so third-party `http://` links are not
  incorrectly reported as target vulnerabilities.
- Custom JSON rules for engagement-specific secrets and exclusions.
- CI-friendly exit status: exits `1` when critical or high findings are present.

## Install

Clone and run with Python 3.8+:

```bash
git clone https://github.com/black3dm0nd/jsrecon
cd jsrecon
python3 jsrecon.py -h
```

Install as a `jsrecon` command:

```bash
pip install .
jsrecon -h
```

Install optional extras:

```bash
pip install -r requirements.txt
```

If `jsbeautifier` is unavailable, `jsrecon` uses a built-in fallback beautifier.
If `requests` is unavailable, it falls back to Python's standard-library
`urllib` fetcher.

## Quick Start

```bash
# Scan one local bundle and print a text report.
python3 jsrecon.py -i app.min.js

# Scan a remote JavaScript file through Burp.
python3 jsrecon.py -u https://target/static/main.js --proxy http://127.0.0.1:8080 -k

# Crawl a page recursively and scan discovered JavaScript.
python3 jsrecon.py -u https://target/ --crawl --depth 3

# Inventory JavaScript URLs only; do not fetch or scan them.
python3 jsrecon.py -u https://target/ --extract

# Recover original sources from source maps and scan those too.
python3 jsrecon.py -u https://target/static/app.min.js --source-maps

# Scan many URLs and write multiple report formats.
python3 jsrecon.py -l js_urls.txt -o loot/report -f html,json,csv,txt

# Read JavaScript from stdin and output JSON secrets only.
cat app.js | python3 jsrecon.py --secrets -f json

# Build a directory wordlist from discovered paths.
python3 jsrecon.py -i app.js --dirs -f txt
```

## Inputs

| Flag | Description |
| --- | --- |
| `-i, --input FILE` | Local JavaScript file. Repeatable. |
| `-u, --url URL` | Remote JavaScript URL, or an HTML page when used with `--crawl`. Repeatable. |
| `-l, --list FILE` | File containing one URL or local path per line. `#` comments are ignored. |
| stdin | Piped JavaScript, used automatically when no `-i`, `-u`, or `-l` is provided. |

## Discovery

| Flag | Description |
| --- | --- |
| `--crawl` | Treat URL targets as HTML pages, discover JavaScript recursively, fetch it, and scan it. |
| `--extract` | Inventory referenced JavaScript URLs and exit without fetching or scanning them. |
| `--depth N` | JavaScript-to-JavaScript recursion depth for `--crawl`. Default: `3`. |
| `--max-files N` | Maximum files fetched while crawling. Default: `300`. |
| `--source-maps` | Recover and scan original sources from external or inline source maps. |

`--crawl` discovers `<script src>`, inline scripts, module/preload links,
dynamic `import()`, `importScripts()`, generic `.js` references, and best-effort
webpack lazy-chunk URLs.

## Output

| Flag | Description |
| --- | --- |
| `-o, --output PATH` | Write the report to `PATH`. If the extension is `.txt`, `.html`, `.json`, `.csv`, or `.xml`, that extension selects the format. Otherwise one `PATH.<format>` file is written per requested format. |
| `-f, --format LIST` | Comma-separated formats: `txt`, `html`, `json`, `csv`, `xml`. Default: `txt`. |
| `--no-color` | Disable ANSI color in terminal output. |
| `-q, --quiet` | Suppress banner and progress messages on stderr. |
| `-v, --verbose` | Show affected files for every finding, including info-level inventory items. |
| `--group source\|category` | Group by source file or aggregate by category. Default: `category`. |
| `-s, --summary` | Show counts plus critical/high findings only in text and HTML reports. |
| `--max-per-category N` | Limit text/HTML rows per category. `0` means unlimited. |

Examples:

```bash
# Exact output file from extension.
python3 jsrecon.py -i app.js -o report.html

# Basename plus multiple formats.
python3 jsrecon.py -i app.js -o reports/app -f txt,json,xml

# Compact triage view for a noisy crawl.
python3 jsrecon.py -u https://target/ --crawl --summary --max-per-category 20
```

## Filters

All categories are shown by default. Passing one or more category flags narrows
the report to only those categories.

| Flag | Category |
| --- | --- |
| `--secrets` | Keys, tokens, passwords, private keys, connection strings. |
| `--vulns` | Concrete client-side misconfigurations. |
| `--dom` | Potential DOM-based XSS. |
| `--sourcemaps` | Source maps found or recovered. |
| `--links` | URLs and endpoints. |
| `--dirs` | Directories and path prefixes. |
| `--params` | Query-string parameter names. |
| `--domains` | Domains and subdomains. |
| `--ips` | IPv4 addresses, with private ranges flagged. |
| `--emails` | Email addresses. |
| `--s3` | S3 bucket URLs. |
| `--comments` | Interesting developer comments. |

Additional tuning:

| Flag | Description |
| --- | --- |
| `--min-severity LEVEL` | Drop findings below `critical`, `high`, `medium`, `low`, or `info`. Default: `info`. |
| `--entropy` | Enable low-confidence high-entropy string detection. Off by default. |
| `--scope DOMAIN[,...]` | In-scope domains for scope-sensitive checks. URL targets are added automatically. |
| `--rules FILE` | JSON file containing custom secret patterns and/or excludes. |
| `--exclude REGEX` | Drop findings whose value matches `REGEX`. Repeatable. |

## Custom Rules

Use a JSON rules file to add engagement-specific token formats or suppress known
noise without changing code.

```json
{
  "secrets": [
    {
      "name": "Acme Internal Token",
      "regex": "acme_[0-9a-f]{20}",
      "severity": "critical"
    },
    {
      "name": "Legacy Session",
      "regex": "SESS=([A-Za-z0-9]{32})",
      "group": 1
    }
  ],
  "exclude": [
    "cdn\\.vendor\\.com",
    "GA-\\d{6,}",
    "/assets/vendor/"
  ]
}
```

```bash
python3 jsrecon.py -u https://target/ --crawl --rules engagement.json
python3 jsrecon.py -i app.js --exclude 'googletagmanager' --exclude 'cdn\.jsdelivr'
```

`severity` defaults to `medium`. `group` defaults to `0` and selects the capture
group that contains the secret value. Invalid regexes or severities fail fast
with a clear error.

## Network Options

| Flag | Description |
| --- | --- |
| `-H, --header 'K: V'` | Extra request header. Repeatable. |
| `-b, --cookie VAL` | Cookie header value. |
| `--proxy URL` | HTTP(S) proxy, such as Burp at `http://127.0.0.1:8080`. |
| `-k, --insecure` | Skip TLS certificate verification. |
| `-t, --timeout SEC` | Request timeout. Default: `20`. |
| `--threads N` | Concurrent fetches for URL lists. Default: `5`; forced to `1` by `--stealth`. |

By default, `jsrecon` uses a plain current-browser User-Agent without a tool
identifier.

## Stealth Mode

`--stealth` lowers crawl footprint by rotating realistic browser User-Agents,
sending browser-like headers, adding natural `Referer` values, using one
connection, and applying a randomized delay.

| Flag | Description |
| --- | --- |
| `--stealth` | Enable low-footprint fetch behavior. Sets `--delay 0.75 --jitter 1.5` unless overridden. |
| `--delay SEC` | Base seconds to wait before each request. |
| `--jitter SEC` | Additional random `0..SEC` seconds before each request. |

```bash
python3 jsrecon.py -u https://target/ --crawl --stealth
python3 jsrecon.py -u https://target/ --crawl --proxy http://127.0.0.1:8080 --delay 2 --jitter 3
```

For the lowest profile, combine `--stealth` with conservative `--depth` and
`--max-files` values.

## What It Detects

### Secrets

`jsrecon` includes 30+ built-in secret patterns, including AWS, Google, GCP,
Firebase, Azure, Slack, GitHub, GitLab, Stripe, Square, PayPal/Braintree,
Twilio, SendGrid, Mailgun, Mailchimp, Postman, NPM, Heroku, Shopify, Facebook,
Twitter bearer tokens, Discord, Algolia, Datadog, JWTs, private-key blocks,
authorization headers, basic-auth-in-URL, database connection strings, generic
API-key assignments, and hard-coded password assignments.

Obvious placeholders such as examples, dummy values, redacted values, and
template markers are demoted automatically. Generic high-entropy string
detection is available with `--entropy` but remains off by default because it is
noisier.

### Attack Surface

The extractor inventories links, endpoints, derived directory prefixes, query
parameters, domains, subdomains, IPv4 addresses, email addresses, and S3 bucket
URLs. Private IPv4 ranges are flagged as potential internal infrastructure
leaks.

### DOM-XSS

DOM-XSS candidates are reported only when at least one source and one dangerous
sink appear in the same file. A lone source or lone sink is not reported as
DOM-XSS.

Common sources include `location.*`, `document.URL`, `document.referrer`,
`document.cookie`, `window.name`, message events, `URLSearchParams`,
`history.state`, and storage reads.

Common sinks include `eval`, `Function`, string-based timers, `innerHTML`,
`outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`,
`createContextualFragment`, `DOMParser.parseFromString`, jQuery HTML insertion,
React `dangerouslySetInnerHTML`, Angular trust bypass APIs, URL assignments, and
`window.open`.

DOM-XSS findings are rated at most high because source/sink co-occurrence is a
strong lead, not proof of data flow.

### Misconfigurations

Concrete client-side issues include message listeners without origin checks,
wildcard `postMessage`, wildcard CORS strings, open-redirect-style navigation,
disabled TLS verification, `document.domain` relaxation, direct `__proto__`
writes, and in-scope cleartext HTTP endpoints.

## Reports

Text reports are designed for terminal triage. HTML reports include severity and
text filters. JSON, CSV, and XML reports preserve structured output for tooling,
CI, diffing, or later analysis.

Findings are aggregated by category by default. Identical findings across many
chunks collapse into one row with an occurrence count and source list. Use
`--group source` for a per-file view.

## Project Structure

```text
jsrecon/
|-- jsrecon.py              # CLI entry point, argument parsing, orchestration
|-- core/
|   |-- __init__.py         # package metadata and version
|   |-- beautifier.py       # jsbeautifier wrapper and stdlib fallback
|   |-- discovery.py        # crawl discovery, webpack chunks, source maps
|   |-- extractor.py        # extraction engine, filtering, aggregation
|   |-- fetcher.py          # local, URL, URL-list, and stdin loading
|   |-- hints.py            # exploitation hints for report findings
|   |-- patterns.py         # regex libraries, categories, severities
|   `-- reporter.py         # txt, html, json, csv, and xml renderers
|-- examples/
|   |-- rules.example.json  # custom rules example
|   `-- sample.js           # fake-secret fixture
|-- tests/
|   `-- test_jsrecon.py     # unittest smoke and behavior coverage
|-- requirements.txt        # optional extras only
|-- pyproject.toml          # package metadata and console script
|-- LICENSE                 # MIT license
`-- README.md
```

## Development

Run the test suite from the repository root:

```bash
python3 -m unittest -v
```

Useful local checks:

```bash
python3 jsrecon.py -h
python3 jsrecon.py -i examples/sample.js --summary
python3 jsrecon.py -i examples/sample.js -o reports/jsrecon-report.json
```

The package exposes a console script through `pyproject.toml`:

```toml
[project.scripts]
jsrecon = "jsrecon:main"
```

## Roadmap

- Real JavaScript AST data-flow tracking for lower-noise DOM-XSS paths.
- Optional live secret validation with explicit opt-in and read-only checks.
- Endpoint export to `curl`, `ffuf`, Burp Intruder, Postman, or OpenAPI-style
  collections.
- Dedicated wordlist export mode for directories, params, and filenames.
- Baseline diffing to show only new findings between bundle versions.
- `gf`, nuclei, and SARIF exports for broader workflow integration.
- HTTP caching with ETag and `If-Modified-Since` for large repeat crawls.
- WebAssembly, base64 blob, escaped-string, and `String.fromCharCode`
  de-obfuscation before scanning.
- Better config-secret context, such as reporting surrounding object keys and
  variable names for bare values.

## License

`jsrecon` is released under the MIT License. See [LICENSE](LICENSE).
