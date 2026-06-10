<div align="center">

```
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Automated async web security scanner for penetration testers and developers**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/github/license/lutzashl290788-cell/webscan?style=flat-square&color=00d26a)](LICENSE)
[![Stars](https://img.shields.io/github/stars/lutzashl290788-cell/webscan?style=flat-square&color=ffd700)](https://github.com/lutzashl290788-cell/webscan/stargazers)
[![Issues](https://img.shields.io/github/issues/lutzashl290788-cell/webscan?style=flat-square&color=ff6b6b)](https://github.com/lutzashl290788-cell/webscan/issues)
[![PyPI](https://img.shields.io/pypi/v/webscan?style=flat-square&color=00d26a&logo=pypi&logoColor=white)](https://pypi.org/project/webscan)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

</div>

---

## ⚡ Quick Start

```bash
pip install webscan
webscan -t https://example.com
```

> **Legal notice:** Use only on systems you own or have written permission to test.

---

## 🎯 What it does

WebScan crawls your target, discovers all endpoints and forms, then fires every plugin against them — all concurrently via `aiohttp`.

```
$ webscan -t https://example.com --depth 3 -v

🔍 Starting scan → https://example.com
🕷  Crawler found 47 URLs, 12 forms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:18

 🔴 CRITICAL  /.env exposed
    URL: https://example.com/.env
    Fix: Remove from webroot, add to .gitignore

 🟠 HIGH      Missing HSTS header
    URL: https://example.com
    Fix: Add Strict-Transport-Security: max-age=31536000

 🟡 MEDIUM    CORS wildcard (*)
    URL: https://example.com/api/data
    Fix: Restrict Access-Control-Allow-Origin to known origins

 ✅ Scan complete: 3 findings (1 CRITICAL · 1 HIGH · 1 MEDIUM)
    Report saved → reports/scan.json | reports/scan.md
```

---

## 🧩 Plugins

| Plugin | Checks |
|--------|--------|
| `config_files` | 50+ exposed files: `.env`, `.git/config`, `wp-config.php`, SSH keys, SQL dumps |
| `headers` | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| `directories` | `/admin`, `/backup`, `/.git/`, phpMyAdmin, exposed panels |
| `sql_injection` | Error-based, boolean blind, time-based — MySQL/PgSQL/SQLite/MSSQL |
| `xss` | Reflected, stored, DOM-based + WAF bypass payloads |
| `cors` | Reflected Origin, wildcard `*`, credentials exposure |
| `cookies` | Missing `Secure` / `HttpOnly` / `SameSite` |
| `http_methods` | Dangerous: `PUT`, `DELETE`, `TRACE`, `CONNECT` |
| `path_traversal` | `../../../etc/passwd` and encoded variants |
| `open_redirect` | `?next=`, `?redirect=`, `?url=` parameter abuse |
| `ssrf` | AWS metadata, internal hosts, out-of-band detection |
| `ssl_tls` | Weak ciphers, expired certs, SSLv2/v3/TLS1.0, missing HSTS |
| `tech_fingerprint` | CMS, framework, server version → CVE lookup |
| `subdomains` | DNS bruteforce + Certificate Transparency (crt.sh) |

---

## 🚀 Usage

```bash
# Single target, all plugins
webscan -t https://example.com

# Multiple targets with auth
webscan -t https://a.com https://b.com --cookie "session=abc123"

# Deep crawl with proxy (Burp Suite)
webscan -t https://example.com --depth 5 --proxy http://127.0.0.1:8080

# Only critical findings, save report
webscan -t https://example.com --min-severity high -o ./reports/scan

# Select specific plugins
webscan -t https://example.com --plugins xss sql_injection headers

# Targets from file
webscan -f targets.txt --format json html sarif
```

### All flags

```
  -t URL [URL ...]       Target URL(s)
  -f FILE                File with one URL per line
  --plugins NAME [...]   Plugins to run (default: all)
  --depth N              Crawler depth (default: 2)
  --min-severity LEVEL   Filter: low | medium | high | critical
  -o PATH                Report base path (no extension)
  --format FMT [...]     json | md | html | sarif | csv
  --proxy URL            HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)
  --cookie STRING        Session cookie(s)
  --header "K: V"        Extra header (repeatable)
  --basic-auth user:pass HTTP Basic auth
  --login-url URL        Form-based login URL
  --login-data STRING    Form login POST data
  --user-agent STRING    Custom User-Agent
  --random-agent         Random User-Agent from built-in list
  --delay N              Delay between requests (seconds)
  --random-delay         Randomize delay ×0.5–×1.5
  --rate-limit N         Max requests per second
  --timeout SEC          Per-request timeout (default: 10)
  -c N                   Concurrent targets (default: 10)
  --no-verify-ssl        Disable SSL certificate verification
  --ignore-robots        Ignore robots.txt
  -v                     Verbose: print every finding
  -q                     Quiet: suppress stdout except errors
```

---

## 🔌 Writing a plugin

```python
from __future__ import annotations
import aiohttp
from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "What it checks in one line"

    async def run(self, target: str, session: aiohttp.ClientSession) -> list[Finding]:
        findings: list[Finding] = []
        # your checks here
        return findings
```

Register in `webscan/cli.py` → `ALL_PLUGINS["my_plugin"] = MyPlugin` — that's it.

---

## 📊 Output formats

| Format | Flag | Use case |
|--------|------|----------|
| JSON | `--format json` | CI/CD, scripting, integrations |
| Markdown | `--format md` | Human review, GitHub PRs |
| HTML | `--format html` | Stakeholder reports |
| SARIF | `--format sarif` | GitHub Security tab, VS Code |
| CSV | `--format csv` | Excel, Jira, Notion |

**CI integration** — exits with code `1` when any CRITICAL or HIGH finding is detected.

---

## ⚙️ CI/CD

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  webscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install webscan
      - run: webscan -t ${{ secrets.STAGING_URL }} --min-severity high --format sarif -o report
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```

### Docker

```bash
docker run --rm ghcr.io/lutzashl290788-cell/webscan -t https://example.com

# With reports
docker run --rm -v $(pwd)/reports:/reports \
  ghcr.io/lutzashl290788-cell/webscan \
  -t https://example.com -o /reports/scan
```

---

## 🏗 Architecture

```
webscan/
├── cli.py              # Entry point, argument parsing
├── scanner.py          # Async scan orchestrator
├── crawler.py          # Async spider with JS endpoint extraction
├── models.py           # Finding, Severity, ScanResult dataclasses
├── auth.py             # Auth: cookie, bearer, basic, form-based
├── reporter.py         # JSON / MD / HTML / SARIF / CSV output
└── plugins/
    ├── base.py         # BasePlugin ABC
    ├── config_files.py
    ├── headers.py
    ├── sql_injection.py
    ├── xss.py
    └── ...             # one file per plugin
```

---

## 📦 Installation

```bash
# pip
pip install webscan

# pipx (isolated)
pipx install webscan

# from source
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan && pip install -e ".[dev]"
```

**Requirements:** Python ≥ 3.10, aiohttp ≥ 3.9

---

## 🤝 Contributing

PRs are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## ⚖️ Legal

WebScan is for **authorized security testing only**. Only use on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.

---

<div align="center">

Made with ☕ and too many CVEs

**[⭐ Star if useful](https://github.com/lutzashl290788-cell/webscan/stargazers)** · **[🐛 Report bug](https://github.com/lutzashl290788-cell/webscan/issues)** · **[💡 Request feature](https://github.com/lutzashl290788-cell/webscan/issues)**

</div>
