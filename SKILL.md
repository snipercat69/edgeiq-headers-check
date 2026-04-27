# SKILL.md — headers.check

HTTP security headers analyzer for developers and security teams.

## Overview
`headers-check` scans any URL's HTTP security response headers and grades them A-F. Free tier: 20 scans/day. Pro ($5/mo): unlimited scans + detailed remediation guide.

## Usage
```bash
python3 headers_check.py --url https://example.com
python3 headers_check.py --url https://example.com --pro
```

## Free Tier
- 20 scans/day
- Overall A-F security grade
- List of present/missing/misconfigured headers

## Pro Tier ($5/mo)
- Unlimited scans
- Full remediation guide for each missing/misconfigured header
- Activate with `--pro` flag

## Pro Upgrade
https://buy.stripe.com/bJedRb8dZeJD9Ig0487wA0w

## Security Headers Checked
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection
- Cache-Control

## License
Pro users must maintain active subscription. See Stripe link for terms.


---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
