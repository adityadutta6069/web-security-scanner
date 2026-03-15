"""
Web Security Scanner - Core Engine
Checks: Security Headers, SSL/TLS, XSS indicators, Info Disclosure
"""

import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
import json
import re
from datetime import datetime


# ─────────────────────────────────────────
#  Data Classes
# ─────────────────────────────────────────

class Finding:
    def __init__(self, name, status, severity, detail, remediation=None):
        """
        status   : 'pass' | 'fail' | 'warn' | 'info'
        severity : 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS'
        """
        self.name = name
        self.status = status
        self.severity = severity
        self.detail = detail
        self.remediation = remediation

    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "detail": self.detail,
            "remediation": self.remediation,
        }


# ─────────────────────────────────────────
#  HTTP Helper
# ─────────────────────────────────────────

def fetch(url, follow_redirects=True, timeout=8):
    """
    Returns (final_url, status_code, headers_dict, body_snippet, error)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WebSecScanner/1.0 (Educational)"},
    )
    try:
        handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(handler)
        if not follow_redirects:
            opener = urllib.request.build_opener(
                handler,
                urllib.request.HTTPRedirectHandler,
            )
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="ignore")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.geturl(), resp.status, headers, body, None
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return url, e.code, headers, "", None
    except Exception as exc:
        return url, 0, {}, "", str(exc)


def get_cert_info(hostname, port=443):
    """Returns cert dict or None."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                return {"cert": cert, "protocol": protocol, "cipher": cipher}
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Certificate error: {e}"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────
#  Check Modules
# ─────────────────────────────────────────

def check_security_headers(headers, url):
    findings = []

    # 1. Content-Security-Policy
    csp = headers.get("content-security-policy")
    if csp:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append(Finding(
                "Content-Security-Policy",
                "warn", "MEDIUM",
                f"CSP present but uses unsafe directives: {csp[:120]}",
                "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives."
            ))
        else:
            findings.append(Finding(
                "Content-Security-Policy",
                "pass", "PASS",
                f"CSP header found with strong policy: {csp[:120]}"
            ))
    else:
        findings.append(Finding(
            "Content-Security-Policy",
            "fail", "HIGH",
            "No Content-Security-Policy header found. This allows XSS and data injection attacks.",
            "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
        ))

    # 2. X-Frame-Options
    xfo = headers.get("x-frame-options")
    if xfo:
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            findings.append(Finding(
                "X-Frame-Options",
                "pass", "PASS",
                f"X-Frame-Options set to '{xfo}' — protects against clickjacking."
            ))
        else:
            findings.append(Finding(
                "X-Frame-Options",
                "warn", "LOW",
                f"X-Frame-Options value '{xfo}' is non-standard.",
                "Use DENY or SAMEORIGIN."
            ))
    else:
        findings.append(Finding(
            "X-Frame-Options",
            "fail", "MEDIUM",
            "Missing X-Frame-Options header. Site may be embeddable in iframes (clickjacking risk).",
            "Add: X-Frame-Options: DENY"
        ))

    # 3. X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        findings.append(Finding(
            "X-Content-Type-Options",
            "pass", "PASS",
            "X-Content-Type-Options: nosniff is set. Prevents MIME-type sniffing."
        ))
    else:
        findings.append(Finding(
            "X-Content-Type-Options",
            "fail", "MEDIUM",
            "Missing X-Content-Type-Options header. Browser may MIME-sniff responses.",
            "Add: X-Content-Type-Options: nosniff"
        ))

    # 4. Strict-Transport-Security
    hsts = headers.get("strict-transport-security")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        if max_age >= 31536000:
            findings.append(Finding(
                "Strict-Transport-Security",
                "pass", "PASS",
                f"HSTS enabled with max-age={max_age}s. Good."
            ))
        else:
            findings.append(Finding(
                "Strict-Transport-Security",
                "warn", "MEDIUM",
                f"HSTS max-age too short: {max_age}s (minimum recommended: 31536000).",
                "Set max-age to at least 31536000 (1 year). Add includeSubDomains."
            ))
    else:
        if url.startswith("https"):
            findings.append(Finding(
                "Strict-Transport-Security",
                "fail", "MEDIUM",
                "HTTPS site missing HSTS header. Browsers won't enforce HTTPS on future visits.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ))
        else:
            findings.append(Finding(
                "Strict-Transport-Security",
                "info", "INFO",
                "HSTS not applicable for HTTP sites."
            ))

    # 5. Referrer-Policy
    rp = headers.get("referrer-policy")
    safe_policies = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
    if rp:
        if rp.lower() in safe_policies:
            findings.append(Finding(
                "Referrer-Policy",
                "pass", "PASS",
                f"Referrer-Policy is '{rp}' — safe policy."
            ))
        else:
            findings.append(Finding(
                "Referrer-Policy",
                "warn", "LOW",
                f"Referrer-Policy is '{rp}', which may leak URLs in referrer headers.",
                "Use: Referrer-Policy: strict-origin-when-cross-origin"
            ))
    else:
        findings.append(Finding(
            "Referrer-Policy",
            "warn", "LOW",
            "No Referrer-Policy header. Browser default may send full URL as referrer.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"
        ))

    # 6. Permissions-Policy
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if pp:
        findings.append(Finding(
            "Permissions-Policy",
            "pass", "PASS",
            f"Permissions-Policy found: {pp[:100]}"
        ))
    else:
        findings.append(Finding(
            "Permissions-Policy",
            "warn", "LOW",
            "No Permissions-Policy header. Browser features (camera, mic, geolocation) may be accessible.",
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ))

    # 7. CORS
    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        findings.append(Finding(
            "CORS Policy",
            "fail", "HIGH",
            "Access-Control-Allow-Origin: * allows any origin to read responses. Dangerous for authenticated APIs.",
            "Restrict CORS to specific trusted origins."
        ))
    elif acao:
        findings.append(Finding(
            "CORS Policy",
            "pass", "PASS",
            f"CORS restricted to: {acao}"
        ))
    else:
        findings.append(Finding(
            "CORS Policy",
            "info", "INFO",
            "No CORS headers found — default same-origin policy applies."
        ))

    return findings


def check_ssl(url, headers):
    findings = []
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    is_https = url.startswith("https")

    # 1. HTTPS usage
    if is_https:
        findings.append(Finding(
            "HTTPS in use",
            "pass", "PASS",
            "Site is served over HTTPS."
        ))
    else:
        findings.append(Finding(
            "HTTPS in use",
            "fail", "HIGH",
            "Site is served over plain HTTP. All traffic is unencrypted.",
            "Obtain a TLS certificate (e.g. Let's Encrypt) and redirect all HTTP to HTTPS."
        ))

    # 2. Certificate info
    if is_https and hostname:
        info = get_cert_info(hostname)
        if "error" in info:
            findings.append(Finding(
                "TLS Certificate",
                "fail", "HIGH",
                f"Certificate issue: {info['error']}",
                "Renew or fix your TLS certificate."
            ))
        elif info:
            cert = info.get("cert", {})
            proto = info.get("protocol", "unknown")
            cipher_name = info.get("cipher", ("?", "?", "?"))[0]

            # Expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(Finding("Certificate expiry", "fail", "HIGH",
                            "Certificate has EXPIRED!", "Renew immediately."))
                    elif days_left < 30:
                        findings.append(Finding("Certificate expiry", "warn", "MEDIUM",
                            f"Certificate expires in {days_left} days.", "Renew soon."))
                    else:
                        findings.append(Finding("Certificate expiry", "pass", "PASS",
                            f"Certificate valid for {days_left} more days (expires {not_after})."))
                except Exception:
                    findings.append(Finding("Certificate expiry", "info", "INFO", f"Expires: {not_after}"))

            # TLS version
            weak_protos = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
            if any(w in proto for w in weak_protos):
                findings.append(Finding(
                    "TLS version",
                    "fail", "HIGH",
                    f"Server uses deprecated protocol: {proto}",
                    "Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2 or 1.3 only."
                ))
            else:
                findings.append(Finding(
                    "TLS version",
                    "pass", "PASS",
                    f"Protocol: {proto}, Cipher: {cipher_name}"
                ))
    else:
        if not is_https:
            findings.append(Finding(
                "TLS Certificate",
                "fail", "HIGH",
                "No TLS — certificate check skipped.",
                "Enable HTTPS first."
            ))

    # 3. HTTP → HTTPS redirect
    if not is_https:
        http_url = url
        https_url = url.replace("http://", "https://", 1)
        findings.append(Finding(
            "HTTP to HTTPS redirect",
            "fail", "MEDIUM",
            "Site does not use HTTPS. No redirect check needed — upgrade to HTTPS entirely.",
            "Configure server to redirect all HTTP requests to HTTPS."
        ))
    else:
        http_url = url.replace("https://", "http://", 1)
        _, status, redir_headers, _, err = fetch(http_url, timeout=5)
        location = redir_headers.get("location", "")
        if err:
            findings.append(Finding(
                "HTTP to HTTPS redirect",
                "warn", "LOW",
                f"Could not test HTTP redirect: {err}"
            ))
        elif status in (301, 302, 307, 308) and "https" in location.lower():
            findings.append(Finding(
                "HTTP to HTTPS redirect",
                "pass", "PASS",
                f"HTTP redirects to HTTPS (status {status})."
            ))
        else:
            findings.append(Finding(
                "HTTP to HTTPS redirect",
                "warn", "MEDIUM",
                f"HTTP version returned status {status}. May not redirect to HTTPS.",
                "Add a 301 redirect from HTTP to HTTPS."
            ))

    # 4. Mixed content risk
    hsts = headers.get("strict-transport-security", "")
    if is_https and not hsts:
        findings.append(Finding(
            "Mixed content risk",
            "warn", "MEDIUM",
            "No HSTS — browser may load HTTP sub-resources (mixed content) without warning.",
            "Enable HSTS and audit all resource URLs to use HTTPS."
        ))
    elif is_https:
        findings.append(Finding(
            "Mixed content risk",
            "pass", "PASS",
            "HSTS present, reducing mixed content risk."
        ))

    return findings


def check_xss_indicators(url, headers, body):
    findings = []
    parsed = urllib.parse.urlparse(url)

    # 1. Query parameter reflection
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        reflected = [k for k, v in params.items() if any(val in body for val in v)]
        if reflected:
            findings.append(Finding(
                "Reflected input in response",
                "fail", "HIGH",
                f"Query parameter values reflected in response body: {reflected}. Potential reflected XSS.",
                "Encode all user-supplied values before outputting to HTML (htmlspecialchars, escape, etc.)."
            ))
        else:
            findings.append(Finding(
                "Reflected input in response",
                "pass", "PASS",
                "URL parameter values not found in response body."
            ))
    else:
        findings.append(Finding(
            "Reflected input in response",
            "info", "INFO",
            "No query parameters in URL to test for reflection."
        ))

    # 2. Inline scripts in page
    inline_scripts = re.findall(r"<script(?!\s+src)[^>]*>", body, re.IGNORECASE)
    if len(inline_scripts) > 3:
        findings.append(Finding(
            "Inline scripts",
            "warn", "MEDIUM",
            f"{len(inline_scripts)} inline <script> blocks found. Each is a potential XSS injection point.",
            "Move scripts to external files. Add CSP with 'nonce' or 'hash' to allow only trusted inline scripts."
        ))
    elif inline_scripts:
        findings.append(Finding(
            "Inline scripts",
            "info", "INFO",
            f"{len(inline_scripts)} inline script block(s) found — low count, verify they are necessary."
        ))
    else:
        findings.append(Finding(
            "Inline scripts",
            "pass", "PASS",
            "No inline <script> blocks detected in response."
        ))

    # 3. X-XSS-Protection (legacy)
    xxp = headers.get("x-xss-protection")
    if xxp:
        if xxp.startswith("1"):
            findings.append(Finding(
                "X-XSS-Protection",
                "warn", "LOW",
                f"X-XSS-Protection: {xxp}. This header is deprecated and can introduce new vulnerabilities in old IE.",
                "Remove this header and rely on CSP instead."
            ))
        elif xxp == "0":
            findings.append(Finding(
                "X-XSS-Protection",
                "info", "INFO",
                "X-XSS-Protection: 0 (disabled). This is acceptable if CSP is in place."
            ))
    else:
        findings.append(Finding(
            "X-XSS-Protection",
            "info", "INFO",
            "No X-XSS-Protection header. This is fine — use CSP instead (modern approach)."
        ))

    # 4. Cookie flags
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        flags = []
        if "httponly" not in set_cookie.lower():
            flags.append("HttpOnly missing")
        if "secure" not in set_cookie.lower():
            flags.append("Secure missing")
        if "samesite" not in set_cookie.lower():
            flags.append("SameSite missing")
        if flags:
            findings.append(Finding(
                "Cookie security flags",
                "fail", "HIGH",
                f"Cookie missing flags: {', '.join(flags)}. Value: {set_cookie[:80]}",
                "Add HttpOnly, Secure, and SameSite=Lax/Strict to all cookies."
            ))
        else:
            findings.append(Finding(
                "Cookie security flags",
                "pass", "PASS",
                "Cookie has HttpOnly, Secure, and SameSite flags set."
            ))
    else:
        findings.append(Finding(
            "Cookie security flags",
            "info", "INFO",
            "No Set-Cookie header in initial response."
        ))

    # 5. Forms without CSRF tokens
    forms = re.findall(r"<form[^>]*>", body, re.IGNORECASE)
    csrf_hints = re.findall(r'name=["\'](?:csrf|_token|authenticity_token|__RequestVerificationToken)["\']', body, re.IGNORECASE)
    if forms:
        if not csrf_hints:
            findings.append(Finding(
                "CSRF token in forms",
                "warn", "HIGH",
                f"{len(forms)} form(s) found but no visible CSRF token field detected.",
                "Add hidden CSRF token fields to all POST forms and validate server-side."
            ))
        else:
            findings.append(Finding(
                "CSRF token in forms",
                "pass", "PASS",
                f"{len(forms)} form(s) found with CSRF token field detected."
            ))
    else:
        findings.append(Finding(
            "CSRF token in forms",
            "info", "INFO",
            "No HTML forms found in response body."
        ))

    # 6. eval() usage
    eval_uses = re.findall(r'\beval\s*\(', body)
    if eval_uses:
        findings.append(Finding(
            "eval() usage detected",
            "warn", "MEDIUM",
            f"Found {len(eval_uses)} use(s) of eval() in page source — potential code injection risk.",
            "Avoid eval(). Use JSON.parse() for data, or structured DOM APIs."
        ))
    else:
        findings.append(Finding(
            "eval() usage",
            "pass", "PASS",
            "No eval() calls detected in page source."
        ))

    return findings


def check_info_disclosure(url, headers, body):
    findings = []

    # 1. Server header
    server = headers.get("server", "")
    if server:
        version_pattern = re.search(r"[\d.]+", server)
        if version_pattern:
            findings.append(Finding(
                "Server header version",
                "fail", "MEDIUM",
                f"Server header exposes software and version: '{server}'. Attackers can target known CVEs.",
                "Configure server to return a generic or empty Server header."
            ))
        else:
            findings.append(Finding(
                "Server header",
                "warn", "LOW",
                f"Server header present (no version): '{server}'.",
                "Consider removing the Server header entirely."
            ))
    else:
        findings.append(Finding(
            "Server header",
            "pass", "PASS",
            "Server header is absent or generic — no version disclosure."
        ))

    # 2. X-Powered-By
    xpb = headers.get("x-powered-by")
    if xpb:
        findings.append(Finding(
            "X-Powered-By disclosure",
            "fail", "MEDIUM",
            f"X-Powered-By exposes technology stack: '{xpb}'.",
            "Remove X-Powered-By header (e.g. in Express: app.disable('x-powered-by'))."
        ))
    else:
        findings.append(Finding(
            "X-Powered-By",
            "pass", "PASS",
            "No X-Powered-By header — technology stack not disclosed."
        ))

    # 3. Version comments in HTML
    version_comments = re.findall(r"<!--.*?(?:v[\d.]+|version|release).*?-->", body, re.IGNORECASE | re.DOTALL)
    if version_comments:
        findings.append(Finding(
            "Version info in HTML comments",
            "warn", "LOW",
            f"Found {len(version_comments)} HTML comment(s) containing version info: {version_comments[0][:80]}",
            "Strip version comments from production HTML output."
        ))
    else:
        findings.append(Finding(
            "Version info in HTML comments",
            "pass", "PASS",
            "No version information found in HTML comments."
        ))

    # 4. robots.txt
    parsed = urllib.parse.urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    _, robots_status, _, robots_body, _ = fetch(robots_url, timeout=5)
    if robots_status == 200:
        sensitive_paths = re.findall(r"Disallow:\s*(/[^\s]+)", robots_body)
        if sensitive_paths:
            findings.append(Finding(
                "robots.txt path disclosure",
                "warn", "LOW",
                f"robots.txt reveals {len(sensitive_paths)} disallowed paths (e.g. {sensitive_paths[0]}). May hint at hidden endpoints.",
                "Avoid listing sensitive paths in robots.txt — attackers read it too."
            ))
        else:
            findings.append(Finding(
                "robots.txt",
                "info", "INFO",
                "robots.txt exists but contains no obviously sensitive paths."
            ))
    else:
        findings.append(Finding(
            "robots.txt",
            "info", "INFO",
            f"robots.txt not found (status {robots_status}) — nothing to disclose."
        ))

    # 5. Directory listing
    trail_url = url.rstrip("/") + "/test_dir_listing_check/"
    _, dl_status, _, dl_body, _ = fetch(trail_url, timeout=4)
    index_of = "index of" in dl_body.lower() or "directory listing" in dl_body.lower()
    if index_of:
        findings.append(Finding(
            "Directory listing",
            "fail", "HIGH",
            "Server appears to expose directory listings — file tree is publicly browsable.",
            "Disable directory listing in your web server config (e.g. Options -Indexes in Apache)."
        ))
    else:
        findings.append(Finding(
            "Directory listing",
            "pass", "PASS",
            "No directory listing detected."
        ))

    # 6. Error page verbosity
    err_url = url.rstrip("/") + "/this_page_does_not_exist_12345"
    _, err_status, _, err_body, _ = fetch(err_url, timeout=5)
    tech_leaks = re.findall(
        r"(traceback|stack trace|exception in|at line \d+|syntax error|undefined variable|php warning|django|flask|express|nginx/\d|apache/\d)",
        err_body, re.IGNORECASE
    )
    if tech_leaks:
        findings.append(Finding(
            "Verbose error pages",
            "fail", "MEDIUM",
            f"404/error page leaks technology details: {tech_leaks[:3]}",
            "Configure custom error pages that don't expose stack traces or framework info."
        ))
    else:
        findings.append(Finding(
            "Verbose error pages",
            "pass", "PASS",
            f"404 page (status {err_status}) doesn't appear to leak technical details."
        ))

    return findings


# ─────────────────────────────────────────
#  Main Scanner
# ─────────────────────────────────────────

def scan(url):
    """Run all checks and return structured report."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    final_url, status_code, headers, body, error = fetch(url)

    result = {
        "target": url,
        "final_url": final_url,
        "status_code": status_code,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "error": error,
        "headers_raw": dict(headers),
        "checks": {}
    }

    if error and status_code == 0:
        result["checks"] = {
            "headers": [Finding("Connection", "fail", "HIGH",
                f"Could not connect to target: {error}").to_dict()],
            "ssl": [],
            "xss": [],
            "info": [],
        }
        result["summary"] = {"total": 1, "passed": 0, "warnings": 0, "failed": 1, "info": 0, "score": 0}
        return result

    h = check_security_headers(headers, final_url)
    s = check_ssl(final_url, headers)
    x = check_xss_indicators(final_url, headers, body)
    i = check_info_disclosure(final_url, headers, body)

    result["checks"] = {
        "headers": [f.to_dict() for f in h],
        "ssl":     [f.to_dict() for f in s],
        "xss":     [f.to_dict() for f in x],
        "info":    [f.to_dict() for f in i],
    }

    all_findings = h + s + x + i
    result["summary"] = {
        "total": len(all_findings),
        "passed": sum(1 for f in all_findings if f.status == "pass"),
        "warnings": sum(1 for f in all_findings if f.status == "warn"),
        "failed": sum(1 for f in all_findings if f.status == "fail"),
        "info": sum(1 for f in all_findings if f.status == "info"),
    }

    passed = result["summary"]["passed"]
    failed = result["summary"]["failed"]
    warned = result["summary"]["warnings"]
    total = result["summary"]["total"]
    score = max(0, round(100 - failed * 12 - warned * 5))
    result["summary"]["score"] = score

    return result
