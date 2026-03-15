# 🛡 Web Security Scanner

An intermediate-level cybersecurity project that performs passive security analysis on any website.

## What It Checks

| Category | Checks |
|---|---|
| **Security Headers** | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS |
| **SSL / TLS** | HTTPS usage, certificate validity & expiry, TLS version, HTTP→HTTPS redirect, mixed content |
| **XSS & Injection** | Reflected parameters, inline scripts, cookie flags, CSRF tokens, eval() usage |
| **Info Disclosure** | Server header, X-Powered-By, HTML comments, robots.txt, directory listing, error verbosity |

---

## Project Structure

```
web-security-scanner/
├── scan.py               ← CLI runner
├── scanner/
│   ├── __init__.py
│   └── engine.py         ← Core scanner logic (all checks)
├── static/
│   └── dashboard.html    ← Browser-based UI (open directly)
└── README.md
```

---

## Setup

**Requirements:** Python 3.8+ only (no external packages needed — uses stdlib only)

```bash
# No pip install needed!
git clone <this-repo>
cd web-security-scanner
```

---

## Usage

### Option 1 — CLI Scanner

```bash
# Basic scan with colored terminal output
python scan.py https://example.com

# Output raw JSON
python scan.py https://example.com --json

# Save a JSON report file
python scan.py https://example.com --report

# Only show failures and warnings (skip passed checks)
python scan.py https://example.com --quiet
```

**Example output:**
```
╔══════════════════════════════════════════╗
║       Web Security Scanner v1.0          ║
║   Educational — Scan only sites you own  ║
╚══════════════════════════════════════════╝

── Security Headers ──────────────────────

  [✗] [HIGH  ] Content-Security-Policy
       No Content-Security-Policy header found.
       → Fix: Add: Content-Security-Policy: default-src 'self'; script-src 'self'

  [✓] [PASS  ] X-Frame-Options
       X-Frame-Options set to 'DENY' — protects against clickjacking.
...

══════════════════════════════════════════════
  Target  : https://example.com
  Score   : 61/100
  Passed  : 12
  Warnings: 4
  Failed  : 2
  Info    : 5
══════════════════════════════════════════════
```

### Option 2 — Browser Dashboard

Open `static/dashboard.html` directly in your browser. The UI connects to the Anthropic API for AI-enhanced analysis. No server needed.

### Option 3 — Use as Python Library

```python
from scanner.engine import scan

result = scan("https://yoursite.com")

print(result["summary"])
# {'total': 26, 'passed': 14, 'warnings': 5, 'failed': 4, 'info': 3, 'score': 57}

for finding in result["checks"]["headers"]:
    if finding["status"] == "fail":
        print(f"[FAIL] {finding['name']}: {finding['remediation']}")
```

---

## How Scoring Works

```
Score = 100 - (failed_checks × 12) - (warning_checks × 5)
Minimum: 0
```

| Score | Grade |
|---|---|
| 85–100 | Excellent |
| 70–84 | Good |
| 50–69 | Needs improvement |
| < 50 | Critical issues |

---

## Learning Objectives

By building this project you learn:

- **OWASP Top 10** — How headers prevent XSS, clickjacking, MIME sniffing
- **TLS/SSL** — Certificate validation, protocol versions, HSTS
- **HTTP Security Headers** — What each header does and why it matters
- **Information Exposure** — What attackers look for in responses
- **Python stdlib** — `urllib`, `ssl`, `socket`, `re` for real network programming

---

## Extending the Project

Ideas to take it further:

- [ ] Add subdomain enumeration
- [ ] Scan for open redirect vulnerabilities  
- [ ] Check for known CVEs via NVD API
- [ ] Add SQLi/XSS payload testing (use only on your own sites!)
- [ ] Build a PDF report generator
- [ ] Add historical scan comparison
- [ ] Integrate with Shodan API for passive recon

---

## ⚠️ Legal & Ethical Notice

Only scan websites you **own** or have **explicit written permission** to test.
Unauthorized scanning may be illegal under computer fraud laws in your jurisdiction.

This tool performs **passive analysis only** — it reads public HTTP responses and does not send malicious payloads.
