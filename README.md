# headers.check — HTTP Security Headers Scanner

Analyze HTTP security headers on any URL. Get an A-F security grade with detailed breakdown.

## Quick Start

```bash
python3 headers_check.py --url https://example.com
```

## Pro Mode (Remediation Guide)

```bash
python3 headers_check.py --url https://example.com --pro
```

## Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| Scans/day | 20 | Unlimited |
| A-F Grade | ✓ | ✓ |
| Header Status | ✓ | ✓ |
| Remediation Guide | | ✓ |

## Security Headers Analyzed

- **Strict-Transport-Security (HSTS)** — Enforces HTTPS
- **Content-Security-Policy (CSP)** — Blocks XSS/injection
- **X-Frame-Options** — Prevents clickjacking
- **X-Content-Type-Options** — Stops MIME sniffing
- **Referrer-Policy** — Controls referrer info
- **Permissions-Policy** — Browser feature access
- **X-XSS-Protection** — Legacy XSS filter
- **Cache-Control** — Caching behavior

## Install Dependencies

```bash
pip install colorama requests
```

## API

```python
from headers_check import fetch_headers, analyze_headers

headers = fetch_headers("https://example.com")
results, grade, score = analyze_headers(headers)
```

## License

Pro subscription required for commercial use.
https://buy.stripe.com/bJedRb8dZeJD9Ig0487wA0w
