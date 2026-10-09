"""Regex pattern libraries used across jsrecon.

Every pattern is compiled once at import time. Patterns are grouped by the
category flag that exposes them so the CLI can turn whole groups on/off.

Categories
----------
secrets   : credentials, API keys, tokens, private keys, hardcoded passwords
links     : URLs / endpoints / paths pulled out of the JS (LinkFinder-style)
dom       : DOM-XSS sources and sinks
vulns     : other client-side bug indicators (eval, postMessage, open redirect...)
comments  : interesting developer comments (TODO / FIXME / hardcoded notes)

Each secret entry is (name, compiled_regex, severity, capture_group).
`capture_group` is the group index holding the *value* (0 = whole match).
"""

import re

# Severity levels used for sorting / colouring output.
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"

SEVERITY_ORDER = {
    SEV_CRITICAL: 0,
    SEV_HIGH: 1,
    SEV_MEDIUM: 2,
    SEV_LOW: 3,
    SEV_INFO: 4,
}

# ---------------------------------------------------------------------------
# SECRETS
# ---------------------------------------------------------------------------
# name, pattern, severity, value-capture-group
_SECRET_DEFS = [
    # --- Cloud / provider keys (high-confidence, low false-positive) --------
    ("AWS Access Key ID", r"""(?<![A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])""", SEV_CRITICAL, 1),
    ("AWS Secret Access Key", r"""(?i)aws(.{0,20})?(?:secret|sk).{0,20}?['"]([A-Za-z0-9/+=]{40})['"]""", SEV_CRITICAL, 2),
    ("AWS MWS Auth Token", r"""amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}""", SEV_HIGH, 0),
    ("Google API Key", r"""AIza[0-9A-Za-z\-_]{35}""", SEV_HIGH, 0),
    ("Google OAuth Client ID", r"""[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com""", SEV_MEDIUM, 0),
    ("Google OAuth Access Token", r"""ya29\.[0-9A-Za-z\-_]+""", SEV_HIGH, 0),
    ("GCP Service Account", r""""type":\s*"service_account""" , SEV_HIGH, 0),
    ("Firebase Database URL", r"""[a-z0-9.\-]+\.firebaseio\.com""", SEV_MEDIUM, 0),
    ("Firebase Cloud Messaging Key", r"""AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}""", SEV_HIGH, 0),
    ("Azure Storage Key", r"""(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{50,}""", SEV_CRITICAL, 0),

    # --- SaaS tokens --------------------------------------------------------
    ("Slack Token", r"""xox[baprs]-[0-9A-Za-z\-]{10,72}""", SEV_HIGH, 0),
    ("Slack Webhook", r"""https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+""", SEV_HIGH, 0),
    ("GitHub Token", r"""gh[pousr]_[0-9A-Za-z]{36,255}""", SEV_CRITICAL, 0),
    ("GitHub Fine-grained PAT", r"""github_pat_[0-9A-Za-z_]{82}""", SEV_CRITICAL, 0),
    ("GitLab PAT", r"""glpat-[0-9A-Za-z\-_]{20}""", SEV_CRITICAL, 0),
    ("Stripe Secret Key", r"""sk_live_[0-9A-Za-z]{24,}""", SEV_CRITICAL, 0),
    ("Stripe Restricted Key", r"""rk_live_[0-9A-Za-z]{24,}""", SEV_HIGH, 0),
    ("Stripe Publishable Key", r"""pk_live_[0-9A-Za-z]{24,}""", SEV_LOW, 0),
    ("Square Access Token", r"""sq0atp-[0-9A-Za-z\-_]{22}""", SEV_HIGH, 0),
    ("Square OAuth Secret", r"""sq0csp-[0-9A-Za-z\-_]{43}""", SEV_HIGH, 0),
    ("PayPal Braintree Token", r"""access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}""", SEV_HIGH, 0),
    ("Twilio API Key", r"""SK[0-9a-fA-F]{32}""", SEV_HIGH, 0),
    ("Twilio Account SID", r"""AC[0-9a-fA-F]{32}""", SEV_MEDIUM, 0),
    ("SendGrid API Key", r"""SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}""", SEV_HIGH, 0),
    ("Mailgun API Key", r"""key-[0-9a-zA-Z]{32}""", SEV_HIGH, 0),
    ("Mailchimp API Key", r"""[0-9a-f]{32}-us[0-9]{1,2}""", SEV_HIGH, 0),
    ("Postman API Key", r"""PMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}""", SEV_HIGH, 0),
    ("NPM Access Token", r"""npm_[0-9A-Za-z]{36}""", SEV_HIGH, 0),
    ("Heroku API Key", r"""(?i)heroku(.{0,20})?['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]""", SEV_HIGH, 2),
    ("Shopify Token", r"""shp(at|ca|pa|ss)_[0-9a-fA-F]{32}""", SEV_HIGH, 0),
    ("Facebook Access Token", r"""EAACEdEose0cBA[0-9A-Za-z]+""", SEV_HIGH, 0),
    ("Twitter Bearer Token", r"""AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{30,}""", SEV_MEDIUM, 0),
    ("Discord Bot Token", r"""[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}""", SEV_HIGH, 0),
    ("Discord Webhook", r"""https://discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z\-_]+""", SEV_MEDIUM, 0),
    ("Algolia Admin Key", r"""(?i)algolia(.{0,20})?['"]([A-Za-z0-9]{32})['"]""", SEV_MEDIUM, 2),
    ("Datadog API Key", r"""(?i)datadog(.{0,20})?['"]([a-f0-9]{32})['"]""", SEV_MEDIUM, 2),

    # --- Generic / structural ----------------------------------------------
    ("JWT (JSON Web Token)", r"""eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}""", SEV_MEDIUM, 0),
    ("Private Key Block", r"""-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY(?: BLOCK)?-----""", SEV_CRITICAL, 0),
    ("Authorization Basic", r"""(?i)authorization['"\s:=]+basic\s+([A-Za-z0-9=+/]{8,})""", SEV_HIGH, 1),
    ("Authorization Bearer", r"""(?i)authorization['"\s:=]+bearer\s+([A-Za-z0-9\-._~+/]{10,})""", SEV_HIGH, 1),
    ("Basic Auth in URL", r"""[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s:@]+)@[^/\s]+""", SEV_HIGH, 1),
    ("Generic API Key assignment", r"""(?i)(?:api[_\-]?key|apikey|client[_\-]?secret|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{12,})['"]""", SEV_MEDIUM, 1),
    ("Hardcoded Password assignment", r"""(?i)(?:password|passwd|pwd|pass)['"]?\s*[:=]\s*['"]([^'"\s]{4,})['"]""", SEV_HIGH, 1),
    ("DB Connection String", r"""(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'"]+""", SEV_HIGH, 0),
]

SECRET_PATTERNS = [
    (name, re.compile(pat), sev, grp) for (name, pat, sev, grp) in _SECRET_DEFS
]

# Substrings that, if present in a *matched secret value*, mark it as a likely
# placeholder / example and demote it (noise reduction).
SECRET_PLACEHOLDERS = (
    "example", "xxxx", "your_", "yourkey", "placeholder", "dummy", "test_key",
    "0000000000", "1234567890", "abcdef", "changeme", "replace", "<", ">",
    "sample", "redacted", "foobar", "{{", "}}", "${",
)

# ---------------------------------------------------------------------------
# LINKS / ENDPOINTS  (LinkFinder-style extraction regex)
# ---------------------------------------------------------------------------
LINK_REGEX = re.compile(r"""
  (?:"|')                               # opening quote
  (
    ((?:[a-zA-Z]{1,10}://|//)           # scheme or protocol-relative
      [^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})   # host + anything
    |
    ((?:/|\.\./|\./)                    # relative path start
      [^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})  # path chars
    |
    ([a-zA-Z0-9_\-/]{1,}/               # relative endpoint with a slash
      [a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-/]{1,}/               # REST-ish endpoint, no extension
      [a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|js|action|html|xml|do)
      (?:[\?|#][^"|']{0,}|))
  )
  (?:"|')                               # closing quote
""", re.VERBOSE)

# Query-string parameter extraction from captured endpoints.
PARAM_REGEX = re.compile(r"""[?&]([A-Za-z0-9_\-\[\]]{1,40})=""")

# Bare domains / subdomains anywhere in the text.
DOMAIN_REGEX = re.compile(
    r"""\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"""
    r"""(?:com|net|org|io|co|dev|app|cloud|gov|edu|xyz|me|ai|sh|info|biz|"""
    r"""internal|local|corp|lan|api|cdn|s3|amazonaws|azurewebsites|herokuapp|"""
    r"""googleapis|cloudfront|digitaloceanspaces|blob))\b""",
    re.IGNORECASE,
)

# IPv4 (with optional port). Private ranges are flagged specially downstream.
IP_REGEX = re.compile(
    r"""\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))"""
    r"""(?::(\d{1,5}))?\b"""
)

EMAIL_REGEX = re.compile(r"""\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b""")

# AWS S3 bucket URLs (handy for takeover / listing checks).
S3_REGEX = re.compile(
    r"""(?:https?://)?(?:[a-z0-9.\-]+\.)?s3[.\-][a-z0-9\-]*\.?amazonaws\.com/[^\s"'<>]*"""
    r"""|[a-z0-9.\-]{3,63}\.s3\.amazonaws\.com""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# DOM-XSS: sources (attacker-controlled) and sinks (dangerous execution)
# ---------------------------------------------------------------------------
# SOURCES = attacker-influenceable inputs. Patterns target READS: a trailing
# `(?!\s*=(?!=))` lookahead skips the assignment form (`x.href = ...`, which is
# a sink, not a source) while still matching comparisons (`===`) and reads.
_READ = r"""(?!\s*=(?!=))"""   # not an assignment target (allows == / ===)

DOM_SOURCES = [
    ("location.hash", re.compile(r"""\blocation\s*\.\s*hash\b""" + _READ)),
    ("location.search", re.compile(r"""\blocation\s*\.\s*search\b""" + _READ)),
    ("location.pathname", re.compile(r"""\blocation\s*\.\s*pathname\b""" + _READ)),
    ("location.href", re.compile(r"""\blocation\s*\.\s*href\b""" + _READ)),
    ("location (object)", re.compile(r"""(?<![.\w])(?:window|document|self|top|parent)\s*\.\s*location\b(?!\s*\.\s*(?:assign|replace))""" + _READ)),
    ("document.URL", re.compile(r"""\bdocument\s*\.\s*URL\b""")),
    ("document.documentURI", re.compile(r"""\bdocument\s*\.\s*documentURI\b""")),
    ("document.baseURI", re.compile(r"""\bdocument\s*\.\s*baseURI\b""")),
    ("document.referrer", re.compile(r"""\bdocument\s*\.\s*referrer\b""")),
    ("document.cookie", re.compile(r"""\bdocument\s*\.\s*cookie\b""" + _READ)),
    ("window.name", re.compile(r"""(?<![.\w])(?:window|self)\s*\.\s*name\b""" + _READ)),
    ("message event data (postMessage)", re.compile(r"""\baddEventListener\s*\(\s*['"]message['"]|\bonmessage\s*=""")),
    ("URLSearchParams", re.compile(r"""\bURLSearchParams\s*\(""")),
    ("history.state", re.compile(r"""\bhistory\s*\.\s*state\b""")),
    ("localStorage read", re.compile(r"""\blocalStorage\s*\.\s*(?:getItem|key)\s*\(|\blocalStorage\s*\[""")),
    ("sessionStorage read", re.compile(r"""\bsessionStorage\s*\.\s*(?:getItem|key)\s*\(|\bsessionStorage\s*\[""")),
]

# SINKS = APIs that execute or render their argument. HTML-write sinks carry a
# JS/HTML-injection (XSS) risk; URL/navigation sinks carry javascript:-scheme /
# open-redirect risk; code-exec sinks are the most severe.
DOM_SINKS = [
    # --- code execution (most severe) ---
    ("eval()", re.compile(r"""\beval\s*\("""), SEV_CRITICAL),
    ("Function constructor", re.compile(r"""\bnew\s+Function\s*\(|(?<![.\w])Function\s*\("""), SEV_CRITICAL),
    ("setTimeout(string)", re.compile(r"""\bsetTimeout\s*\(\s*['"]"""), SEV_HIGH),
    ("setInterval(string)", re.compile(r"""\bsetInterval\s*\(\s*['"]"""), SEV_HIGH),
    ("execScript()", re.compile(r"""\bexecScript\s*\("""), SEV_HIGH),
    ("jQuery.globalEval()", re.compile(r"""(?:\$|jQuery)\s*\.\s*globalEval\s*\("""), SEV_HIGH),
    # --- HTML injection (XSS) ---
    ("innerHTML =", re.compile(r"""\.\s*innerHTML\s*\+?="""), SEV_HIGH),
    ("outerHTML =", re.compile(r"""\.\s*outerHTML\s*\+?="""), SEV_HIGH),
    ("insertAdjacentHTML()", re.compile(r"""\.\s*insertAdjacentHTML\s*\("""), SEV_HIGH),
    ("document.write()/writeln()", re.compile(r"""\bdocument\s*\.\s*write(?:ln)?\s*\("""), SEV_HIGH),
    ("iframe.srcdoc =", re.compile(r"""\.\s*srcdoc\s*\+?="""), SEV_HIGH),
    ("createContextualFragment()", re.compile(r"""\.\s*createContextualFragment\s*\("""), SEV_HIGH),
    ("DOMParser.parseFromString()", re.compile(r"""\.\s*parseFromString\s*\("""), SEV_MEDIUM),
    ("jQuery.parseHTML()", re.compile(r"""(?:\$|jQuery)\s*\.\s*parseHTML\s*\("""), SEV_MEDIUM),
    ("jQuery .html(arg)", re.compile(r"""\.\s*html\s*\(\s*[^)\s]"""), SEV_MEDIUM),
    ("jQuery DOM-insert (append/after/before/wrap)", re.compile(r"""\.\s*(?:append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner)\s*\(\s*[^)\s]"""), SEV_MEDIUM),
    ("React dangerouslySetInnerHTML", re.compile(r"""dangerouslySetInnerHTML"""), SEV_HIGH),
    ("Angular bypassSecurityTrust*", re.compile(r"""\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\("""), SEV_HIGH),
    ("AngularJS $sce.trustAs*", re.compile(r"""\$sce\s*\.\s*trustAs(?:Html|Js|Css|Url|ResourceUrl)?\s*\("""), SEV_HIGH),
    # --- URL / navigation (javascript: scheme, open redirect) ---
    ("script/iframe .src =", re.compile(r"""\.\s*src\s*=\s*[^=]"""), SEV_MEDIUM),
    ("setAttribute(src|href|srcdoc|data)", re.compile(r"""\.\s*setAttribute\s*\(\s*['"](?:src|href|xlink:href|srcdoc|data|action|formaction)['"]"""), SEV_MEDIUM),
    ("location navigation (assign/replace/href=)", re.compile(r"""\blocation\s*\.\s*(?:assign|replace)\s*\(|\blocation(?:\s*\.\s*href)?\s*=(?!=)"""), SEV_MEDIUM),
    ("window.open()", re.compile(r"""\bwindow\s*\.\s*open\s*\("""), SEV_LOW),
]

# ---------------------------------------------------------------------------
# OTHER VULN / INTERESTING-CONFIG INDICATORS
# ---------------------------------------------------------------------------
# Only concrete, defensible issues — each is a real misconfiguration/weakness,
# not a vague "might be interesting". Low-confidence noise (debug flags) and
# mere endpoints (WebSocket/GraphQL — recon, not a vuln) were removed. Insecure
# HTTP is handled separately so it can be scoped to the target domain.
VULN_PATTERNS = [
    ("postMessage listener without origin check", re.compile(r"""addEventListener\s*\(\s*['"]message['"]|\bonmessage\s*="""), SEV_MEDIUM,
     "Handler reads event.data — confirm event.origin is validated before use."),
    ("postMessage to wildcard origin", re.compile(r"""\.postMessage\s*\([^,]+,\s*['"]\*['"]"""), SEV_MEDIUM,
     "Message posted to '*' — data readable by any framing origin."),
    ("CORS allow-origin wildcard", re.compile(r"""(?i)access-control-allow-origin['"]?\s*[:=]\s*['"]\*['"]"""), SEV_MEDIUM,
     "Wildcard CORS; exploitable for cross-origin read if credentials allowed."),
    ("Open-redirect style navigation", re.compile(r"""(?i)(?:window\.)?location(?:\.href)?\s*=\s*[^=][^;]{0,80}?(?:param|redirect|returnurl|return_url|next|dest|target|url=)"""), SEV_MEDIUM,
     "Navigation target derived from a redirect-like variable — open-redirect candidate."),
    ("Disabled TLS verification", re.compile(r"""(?i)(?:rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false|\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*[:=]\s*['"]?0)"""), SEV_HIGH,
     "TLS certificate validation disabled — MITM possible."),
    ("document.domain relaxation", re.compile(r"""\bdocument\s*\.\s*domain\s*=(?!=)"""), SEV_MEDIUM,
     "document.domain is written — widens same-origin trust to sibling subdomains."),
    ("Prototype-pollution assignment", re.compile(r"""\[\s*['"]__proto__['"]\s*\]\s*=|\.__proto__\s*=|['"]__proto__['"]\s*:"""), SEV_MEDIUM,
     "Direct __proto__ write — prototype-pollution gadget if the key/value is user-controlled."),
]

# Cleartext HTTP URLs — reported ONLY when the host is in the target scope
# (see Extractor.target_domains); a third-party http:// link is not the
# target's vulnerability.
INSECURE_HTTP_REGEX = re.compile(r"""["'](http://[^"'\s]+)["']""", re.IGNORECASE)

# ---------------------------------------------------------------------------
# INTERESTING COMMENTS
# ---------------------------------------------------------------------------
# (Comments are tokenised string-aware in extractor.iter_comments; here we only
# need the keyword filter that decides which comments are worth reporting.)
COMMENT_KEYWORDS = re.compile(
    r"""(?i)\b(?:todo|fixme|hack|xxx|bug|backdoor|password|passwd|secret|api[\s_\-]?key|"""
    r"""token|internal|deprecated|temporary|remove before|do not ship|admin|"""
    r"""username|credential|private|disable[d]?)\b"""
)
