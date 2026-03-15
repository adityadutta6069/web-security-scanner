#!/usr/bin/env python3
"""
Web Security Scanner — CLI Runner
Usage:
    python scan.py https://example.com
    python scan.py https://example.com --json
    python scan.py https://example.com --report
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(__file__))
from scanner.engine import scan


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "PASS": 4}

STATUS_COLORS = {
    "pass":  "\033[92m",   # green
    "fail":  "\033[91m",   # red
    "warn":  "\033[93m",   # yellow
    "info":  "\033[94m",   # blue
}
RESET = "\033[0m"
BOLD  = "\033[1m"

STATUS_ICONS = {
    "pass": "✓",
    "fail": "✗",
    "warn": "!",
    "info": "i",
}

SEV_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[94m",
    "INFO":   "\033[96m",
    "PASS":   "\033[92m",
}


def colorize(text, color_code):
    return f"{color_code}{text}{RESET}"


def print_banner():
    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║       Web Security Scanner v1.0          ║
║   Educational — Scan only sites you own  ║
╚══════════════════════════════════════════╝{RESET}
""")


def print_section(title, findings):
    print(f"\n{BOLD}── {title} {'─' * (40 - len(title))}{RESET}")
    for f in findings:
        status_color = STATUS_COLORS.get(f["status"], "")
        sev_color    = SEV_COLORS.get(f["severity"], "")
        icon = STATUS_ICONS.get(f["status"], "?")
        status_str = colorize(f"[{icon}]", status_color)
        sev_str    = colorize(f"[{f['severity']:6}]", sev_color)
        print(f"  {status_str} {sev_str} {BOLD}{f['name']}{RESET}")
        print(f"       {f['detail']}")
        if f.get("remediation"):
            print(f"       {colorize('→ Fix:', BOLD)} {f['remediation']}")
        print()


def print_summary(summary, target):
    score = summary["score"]
    score_color = "\033[92m" if score >= 75 else "\033[93m" if score >= 50 else "\033[91m"
    print(f"\n{BOLD}{'═' * 46}{RESET}")
    print(f"  Target  : {target}")
    print(f"  Score   : {colorize(str(score) + '/100', score_color + BOLD)}")
    print(f"  Passed  : {colorize(str(summary['passed']), STATUS_COLORS['pass'])}")
    print(f"  Warnings: {colorize(str(summary['warnings']), STATUS_COLORS['warn'])}")
    print(f"  Failed  : {colorize(str(summary['failed']), STATUS_COLORS['fail'])}")
    print(f"  Info    : {colorize(str(summary['info']), STATUS_COLORS['info'])}")
    print(f"{BOLD}{'═' * 46}{RESET}\n")


def save_report(result, filename=None):
    if not filename:
        from datetime import datetime
        safe = result["target"].replace("https://","").replace("http://","").replace("/","_").replace(":","")
        filename = f"report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  Report saved: {filename}")
    return filename


def main():
    parser = argparse.ArgumentParser(description="Web Security Scanner")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--report", action="store_true", help="Save JSON report to file")
    parser.add_argument("--quiet", action="store_true", help="Only show failures and warnings")
    args = parser.parse_args()

    print_banner()
    print(f"  Scanning: {BOLD}{args.url}{RESET}")
    print("  Please wait...\n")

    result = scan(args.url)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    checks = result["checks"]

    if not args.quiet:
        print_section("Security Headers", checks.get("headers", []))
        print_section("SSL / TLS",        checks.get("ssl", []))
        print_section("XSS & Injection",  checks.get("xss", []))
        print_section("Info Disclosure",  checks.get("info", []))
    else:
        # quiet: only non-pass findings
        for section, title in [("headers","Security Headers"),("ssl","SSL/TLS"),("xss","XSS & Injection"),("info","Info Disclosure")]:
            filtered = [f for f in checks.get(section,[]) if f["status"] in ("fail","warn")]
            if filtered:
                print_section(title, filtered)

    print_summary(result["summary"], result["target"])

    if args.report:
        save_report(result)


if __name__ == "__main__":
    main()
