# 🛡️ EdgeIQ Headers Check

**HTTP security headers analyzer — grade your site's security posture in seconds.**

Scan any URL's HTTP security response headers and get an A-F grade with detailed analysis of what's present, missing, and misconfigured.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Analyzes HTTP security headers returned by any URL and assigns a letter grade (A-F) based on industry security standards. Identifies which headers are present, missing, or misconfigured, with actionable remediation guidance.

---

## Key Features

- **A-F security grade** — industry-standard scoring for security header posture
- **9 security headers checked** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cache-Control
- **Remediation guidance** — per-header fix recommendations (Pro)
- **Batch scanning** — check multiple URLs in one run
- **JSON export** — structured results for reporting

---

## Prerequisites

- Python 3.8+
- `requests` library

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-headers-check.git
cd edgeiq-headers-check
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Grade a site's headers
python3 headers_check.py --url https://example.com

# Detailed analysis with headers list
python3 headers_check.py --url https://example.com --verbose

# Pro tier (unlimited + remediation guide)
python3 headers_check.py --url https://example.com --pro
```

---

## Security Headers Checked

| Header | Security Purpose |
|--------|-----------------|
| Strict-Transport-Security | Force HTTPS |
| Content-Security-Policy | XSS/injection protection |
| X-Frame-Options | Clickjacking prevention |
| X-Content-Type-Options | MIME sniffing prevention |
| Referrer-Policy | Control referrer information |
| Permissions-Policy | Restrict browser features |
| X-XSS-Protection | Legacy XSS filter (deprecated but still checked) |
| Cache-Control | Sensitive data caching control |

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 20 scans/day, A-F grade, header list |
| **Pro** | $5/mo | Unlimited scans, full remediation guide, priority support |

---

## Integration with EdgeIQ Tools

- **[EdgeIQ Alerting System](https://github.com/snipercat69/edgeiq-alerting-system)** — alert on poor header grades
- **[EdgeIQ Security Report Generator](https://github.com/snipercat69/edgeiq-security-report-generator)** — include header grades in reports

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-headers-check/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
