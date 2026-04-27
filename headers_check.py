#!/usr/bin/env python3
"""
headers.check — HTTP Security Headers Scanner
Analyzes HSTS, CSP, X-Frame-Options, and more.
Free: 20 scans/day | Pro: unlimited + remediation guide
"""

import argparse
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import json
import os
import re

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class Fore:
        GREEN = RED = YELLOW = BLUE = RESET = MAGENTA = CYAN = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

# Try to import requests for better header handling
try:
    import requests as req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Load licensing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from edgeiq_licensing import is_pro
except ImportError:
    def is_pro():
        return "--pro" in sys.argv


# ── Security headers definition ──────────────────────────────────────────────

HEADERS_DEF = {
    "Strict-Transport-Security": {
        "description": "HSTS — Enforces HTTPS connections",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "severity": "high",
    },
    "Content-Security-Policy": {
        "description": "CSP — Prevents XSS and injection attacks",
        "remediation": "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "severity": "high",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking — controls iframe embedding",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
        "severity": "medium",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is sent",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, etc.)",
        "remediation": "Add header: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "severity": "low",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still useful for old browsers)",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        "severity": "low",
    },
    "Cache-Control": {
        "description": "Controls caching behavior — sensitive pages should not be cached",
        "remediation": "For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate, private",
        "severity": "low",
    },
}

GRADE_THRESHOLDS = {
    "A": 8,
    "B": 6,
    "C": 4,
    "D": 2,
    "F": 0,
}


def fetch_headers(url, timeout=10):
    """Fetch response headers from a URL. Follows redirects."""
    headers_map = {}
    try:
        if HAS_REQUESTS:
            response = req.get(url, timeout=timeout, allow_redirects=True, verify=True)
            for k, v in response.headers.items():
                headers_map[k] = v
        else:
            request = Request(url, method="GET")
            with urlopen(request, timeout=timeout) as response:
                for k, v in response.headers.items():
                    headers_map[k] = v
    except HTTPError as e:
        # Still get headers from error response
        for k, v in e.headers.items():
            headers_map[k] = v
    except URLError as e:
        print(f"{Fore.RED}✗ Failed to fetch {url}: {e.reason}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    return headers_map


def normalize_header(name, value):
    """Check if a header value is properly configured."""
    name_lower = name.lower()
    value_lower = value.lower().strip()

    if name_lower == "strict-transport-security":
        # Must have max-age
        if "max-age" not in value_lower:
            return "misconfigured", "Missing required max-age directive"
        max_age_match = re.search(r"max-age=(\d+)", value_lower)
        if max_age_match and int(max_age_match.group(1)) < 31536000:
            return "misconfigured", f"max-age too short ({max_age_match.group(1)}s, should be ≥31536000)"
        return "present", "Valid HSTS with max-age≥31536000"

    if name_lower == "content-security-policy":
        if not value or value == "*":
            return "misconfigured", "CSP is too permissive"
        return "present", "CSP policy set"

    if name_lower == "x-frame-options":
        if value_lower not in ("deny", "sameorigin"):
            return "misconfigured", f"Invalid value: {value} (use DENY or SAMEORIGIN)"
        return "present", f"X-Frame-Options: {value}"

    if name_lower == "x-content-type-options":
        if value_lower != "nosniff":
            return "misconfigured", f"Invalid value: {value} (use nosniff)"
        return "present", "nosniff set"

    if name_lower == "referrer-policy":
        valid_values = [
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "unsafe-url",
        ]
        if value_lower not in valid_values:
            return "misconfigured", f"Unknown Referrer-Policy value: {value}"
        return "present", f"Referrer-Policy: {value}"

    if name_lower == "permissions-policy":
        if not value or len(value.strip()) == 0:
            return "misconfigured", "Empty Permissions-Policy"
        return "present", "Permissions-Policy set"

    if name_lower == "x-xss-protection":
        if value_lower not in ("1", "1; mode=block", "1; mode=block; report=https://"):
            return "misconfigured", f"Invalid value: {value}"
        return "present", f"X-XSS-Protection: {value}"

    if name_lower == "cache-control":
        return "present", f"Cache-Control: {value}"

    return "present", value


def analyze_headers(headers_map):
    """Analyze headers and return results."""
    results = []
    present_count = 0

    # Normalize header names for matching
    norm_headers = {}
    for k, v in headers_map.items():
        norm_headers[k.lower()] = v

    for header_name, defn in HEADERS_DEF.items():
        header_key = header_name.lower()
        if header_key in norm_headers:
            value = norm_headers[header_key]
            status, detail = normalize_header(header_key, value)
        else:
            status = "missing"
            detail = f"{header_name} not set"

        if status == "present":
            present_count += 1

        results.append({
            "header": header_name,
            "status": status,
            "detail": detail,
            "description": defn["description"],
            "remediation": defn["remediation"],
            "severity": defn["severity"],
        })

    # Calculate grade
    grade = "F"
    for g, threshold in sorted(GRADE_THRESHOLDS.items(), key=lambda x: -ord(x[0])):
        if present_count >= threshold:
            grade = g
            break

    return results, grade, present_count


def print_banner(url, grade, present_count, total_count):
    """Print the scan banner."""
    grade_colors = {
        "A": Fore.GREEN,
        "B": Fore.CYAN,
        "C": Fore.YELLOW,
        "D": Fore.MAGENTA,
        "F": Fore.RED,
    }
    color = grade_colors.get(grade, Fore.WHITE)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}── headers.check ────────────────────────────{Style.RESET_ALL}")
    print(f"{Fore.WHITE}URL:    {Style.BRIGHT}{url}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Grade:   {color}{Style.BRIGHT}{grade}{Style.RESET_ALL}  ({present_count}/{total_count} headers present)")
    print(f"{Fore.CYAN}{Style.BRIGHT}────────────────────────────────────────────────{Style.RESET_ALL}\n")


def print_result(result, colorize=True, verbose=False):
    """Print a single header result."""
    status = result["status"]
    header = result["header"]
    detail = result["detail"]
    desc = result["description"]
    remediation = result["remediation"]

    if status == "present":
        icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if colorize else "✓"
        status_label = f"{Fore.GREEN}PRESENT{Style.RESET_ALL}" if colorize else "PRESENT"
    elif status == "missing":
        icon = f"{Fore.RED}✗{Style.RESET_ALL}" if colorize else "✗"
        status_label = f"{Fore.RED}MISSING{Style.RESET_ALL}" if colorize else "MISSING"
    else:
        icon = f"{Fore.YELLOW}⚠{Style.RESET_ALL}" if colorize else "⚠"
        status_label = f"{Fore.YELLOW}MISCONF{Style.RESET_ALL}" if colorize else "MISCONF"

    print(f"  {icon} {Fore.WHITE}{header}{Style.RESET_ALL} [{status_label}]")
    print(f"      {desc}")
    print(f"      {detail}")

    if verbose:
        print(f"      {Fore.YELLOW}Fix:{Style.RESET_ALL} {remediation}")

    print()


def print_free_notice():
    """Print upgradation nudge for free users."""
    print(f"\n{Fore.YELLOW}── Free tier ─────────────────────────────────{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}20 scans/day limit reached.{Style.RESET_ALL}")
    print(f"  Upgrade to Pro for unlimited scans + remediation guide:")
    print(f"  {Fore.CYAN}https://buy.stripe.com/bJedRb8dZeJD9Ig0487wA0w{Style.RESET_ALL}")
    print()


def main():
    parser = argparse.ArgumentParser(description="headers.check — HTTP Security Headers Scanner")
    parser.add_argument("--url", required=True, help="URL to scan")
    parser.add_argument("--pro", action="store_true", help="Pro mode: show remediation guide")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Check pro status — is_pro() from licensing, --pro flag overrides to True
    actual_pro = is_pro()
    pro_mode = actual_pro or args.pro

    print(f"{Fore.CYAN}Scanning {url}...{Style.RESET_ALL}")

    headers_map = fetch_headers(url)
    results, grade, present_count = analyze_headers(headers_map)

    if args.json:
        output = {
            "url": url,
            "grade": grade,
            "present": present_count,
            "total": len(HEADERS_DEF),
            "headers": results,
        }
        print(json.dumps(output, indent=2))
        return

    print_banner(url, grade, present_count, len(HEADERS_DEF))

    for result in results:
        print_result(result, colorize=COLOR, verbose=pro_mode)

    # Only show free upgrade nudge if user is genuinely on free tier (not a pro licensee)
    if not actual_pro:
        print_free_notice()


if __name__ == "__main__":
    main()
