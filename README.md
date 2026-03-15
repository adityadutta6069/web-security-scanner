# 🛡️ Web Security Scanner

> A passive web security assessment tool built in Python — no external dependencies, runs straight from the terminal.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

---

## 📸 Preview

```
╔══════════════════════════════════════════╗
║       Web Security Scanner v1.0          ║
║   Educational — Scan only sites you own  ║
╚══════════════════════════════════════════╝

── Security Headers ──────────────────────

  [✗] [HIGH  ] Content-Security-Policy
       No Content-Security-Policy header found.
       → Fix: Add: Content-Security-Policy: default-src 'self'

  [✓] [PASS  ] X-Frame-Options
       X-Frame-Options set to 'DENY' — protects against clickjacking.

══════════════════════════════════════════
  Score   : 61/100
  Passed  : 12   Warnings: 4   Failed: 2
══════════════════════════════════════════
```

---

## ✨ Features

- 🔍 **26 security checks** across 4 categories
- 🖥️ **CLI tool** with color-coded output and severity ratings
- 🌐 **Browser dashboard** — open one HTML file, no server needed
- 📄 **JSON report export** for documentation
- ⚡ **Zero dependencies** — uses Python stdlib only (`urllib`, `ssl`, `socket`, `re`)
- 🐍 **Importable as a Python library** in your own scripts

---

## 🔎 What It Scans

| Category | Checks |
|---|---|
| 🔐 **Security Headers** | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS |
| 🔒 **SSL / TLS** | HTTPS usage, certificate validity & expiry, TLS version, HTTP→HTTPS redirect, mixed content |
| 💉 **XSS & Injection** | Reflected parameters, inline scripts, cookie flags, CSRF tokens, eval() usage |
| 🕵️ **Info Disclosure** | Server header, X-Powered-By, HTML comments, robots.txt, directory listing, error verbosity |

---

## 🚀 Getting Started

**Requirements:** Python 3.8+ — nothing else to install.

```bash
# Clone the repo
git clone https://github.com/adityadutta6069/web-security-scanner.git

# Enter the folder
cd web-security-scanner
```

---

## 💻 Usage

### Option 1 — CLI Scanner

```bash
# Basic scan
python scan.py https://example.com

# Only show failures and warnings
python scan.py https://example.com --quiet

# Save results as a JSON report
python scan.py https://example.com --report

# Output raw JSON
python scan.py https://example.com --json
```

### Option 2 — Browser Dashboard

Just open `static/dashboard.html` in your browser — no server or setup needed.

### Option 3 — Use as a Python Library

```python
from scanner.engine import scan

result = scan("https://yoursite.com")

print(result["summary"])
# {'total': 26, 'passed': 14, 'warnings': 5, 'failed': 4, 'score': 57}

for finding in result["checks"]["headers"]:
    if finding["status"] == "fail":
        print(f"[FAIL] {finding['name']}: {finding['remediation']}")
```

---

## 📁 Project Structure

```
web-security-scanner/
├── scan.py                 ← CLI runner
├── scanner/
│   ├── __init__.py
│   └── engine.py           ← Core scanner (all 26 checks)
├── static/
│   └── dashboard.html      ← Browser UI
└── README.md
```

---

## 📊 Scoring System

```
Score = 100 − (failed × 12) − (warnings × 5)
```

| Score | Grade |
|---|---|
| 85 – 100 | ✅ Excellent |
| 70 – 84 | 🟡 Good |
| 50 – 69 | 🟠 Needs improvement |
| Below 50 | 🔴 Critical issues |

---

## 🎓 What You Learn

By exploring this project you get hands-on with:

- **OWASP Top 10** — how headers prevent XSS, clickjacking, MIME sniffing
- **TLS / SSL** — certificate validation, protocol versions, HSTS
- **HTTP Security Headers** — what each one does and why it matters
- **Information Exposure** — what attackers look for in HTTP responses
- **Python networking** — real use of `urllib`, `ssl`, `socket`, `re`

---

## 🛣️ Roadmap

- [ ] Subdomain enumeration
- [ ] Open redirect detection
- [ ] CVE lookup via NVD API
- [ ] SQLi / XSS payload testing
- [ ] PDF report generator
- [ ] Shodan API integration
- [ ] Historical scan comparison

---

## ⚠️ Legal & Ethical Notice

> Only scan websites you **own** or have **explicit written permission** to test.
> Unauthorized scanning may violate computer fraud laws in your jurisdiction.

This tool performs **passive analysis only** — it reads public HTTP responses and never sends malicious payloads.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">Built with 🛡️ for learning cybersecurity</p>
