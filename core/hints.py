"""Short, practical exploitation hints for the exploitable finding classes.

One concise line per issue type — enough to point a tester at the next step,
not a full methodology. Shown only for secrets, DOM-XSS, vulns and S3 findings.
All advice assumes an authorised engagement; for secrets, prefer read-only
validation over any state-changing call.
"""


def _dom_hint(sink):
    s = (sink or "").lower()
    if any(k in s for k in ("eval", "function", "settimeout", "setinterval",
                            "execscript", "globaleval")):
        return ("drive the named source (e.g. #<payload> in the URL) into this "
                "sink; it runs JS directly — try alert(document.domain)")
    if "dangerously" in s or "trust" in s or "bypasssecurity" in s:
        return ("framework escaping is bypassed — if the value is user-controlled "
                "inject <img src=x onerror=alert(1)>")
    if any(k in s for k in ("src", "location", "setattribute", "open")):
        return ("if the URL is source-controlled, test javascript:alert(1) "
                "(href/location) and //evil.tld (open redirect)")
    # HTML-injection family
    return ("inject HTML via the source; <script> won't run from innerHTML — use "
            "<img src=x onerror=alert(1)>; document.write allows <script src>")


_VULN_HINTS = {
    "postMessage listener without origin check":
        "from an attacker origin, frame/open the page and postMessage() a payload; "
        "works if event.origin is not validated",
    "postMessage to wildcard origin":
        "frame the page and add a 'message' listener to capture the data sent to '*'",
    "CORS allow-origin wildcard":
        "from an attacker origin fetch() with credentials:'include' and read the "
        "response (exploitable when the origin is reflected and ACAC:true)",
    "Open-redirect style navigation":
        "set the redirect parameter to //evil.tld (or https://evil.tld) and confirm "
        "off-site navigation; chain to OAuth redirect_uri theft",
    "Disabled TLS verification":
        "validation is off — MITM the client's TLS with a self-signed cert "
        "(e.g. mitmproxy)",
    "document.domain relaxation":
        "get XSS on any sibling subdomain sharing the relaxed domain, then script "
        "this page",
    "Prototype-pollution assignment":
        "send __proto__[x]=y via controllable JSON/query input and hunt for a gadget "
        "that reads the polluted property",
}


def _secret_hint(kind):
    k = (kind or "").lower()
    if "jwt" in k:
        return ("decode & check alg:none / weak HMAC secret (hashcat -m 16500); "
                "test claim tampering")
    if "private key" in k:
        return "key material — can impersonate/sign/decrypt; report, do not misuse"
    if "basic auth" in k or "authorization" in k or "connection string" in k:
        return ("decode the credentials and authenticate only if the service is "
                "in scope and reachable")
    return ("validate read-only to prove it is live (GitHub: GET /user; AWS: "
            "sts get-caller-identity; Stripe: GET /v1/account) — no state changes")


def hint(finding):
    """Return a one-line exploitation hint for *finding*, or '' if none."""
    cat, kind, value = finding.category, finding.kind, finding.value
    if cat == "dom":
        return _dom_hint(value)
    if cat == "vulns":
        if kind.startswith("Insecure HTTP"):
            return ("on-path attacker can read/modify this cleartext request; "
                    "intercept on a shared network (mitmproxy)")
        return _VULN_HINTS.get(kind, "")
    if cat == "secrets":
        return _secret_hint(kind)
    if cat == "s3":
        return ("aws s3 ls s3://<bucket> --no-sign-request; test anonymous "
                "read/write; if the bucket is unclaimed, check for takeover")
    return ""
