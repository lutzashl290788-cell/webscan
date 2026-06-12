<div align="center">

```
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

### Automated async web security scanner for pentesters & developers

*Crawl → discover → audit. 14 plugins, 5 report formats, zero config.*

[![CI](https://img.shields.io/github/actions/workflow/status/lutzashl290788-cell/webscan/ci.yml?style=flat-square&label=CI&logo=githubactions&logoColor=white)](https://github.com/lutzashl290788-cell/webscan/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/github/license/lutzashl290788-cell/webscan?style=flat-square&color=00d26a)](LICENSE)
[![Stars](https://img.shields.io/github/stars/lutzashl290788-cell/webscan?style=flat-square&color=ffd700)](https://github.com/lutzashl290788-cell/webscan/stargazers)
[![Issues](https://img.shields.io/github/issues/lutzashl290788-cell/webscan?style=flat-square&color=ff6b6b)](https://github.com/lutzashl290788-cell/webscan/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

</div>

---

## ⚡ Quick Start

```bash
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan && pip install .

webscan -t https://example.com
```

> **Legal notice:** use only on systems you own or have explicit written permission to test.

---

## 🎯 What it does

WebScan optionally **crawls** your target to discover URLs and forms, then fires every
plugin against them — all concurrently via `aiohttp`. One run, colour-coded findings,
machine-readable reports.

```console
$ webscan -t https://example.com --plugins headers cookies http_methods ssl_tls tech_fingerprint

╔══════════════════════════════════════════════════════════╗
║              WebScan — Security Auditor                 ║
╚══════════════════════════════════════════════════════════╝
  Targets     : 1
  Plugins     : headers, cookies, http_methods, ssl_tls, tech_fingerprint
  Concurrency : 10
  Timeout     : 10s

  [█] 1/1 — https://example.com

  Scan completed  2026-06-11T11:11:51+00:00 → 2026-06-11T11:11:52+00:00
  Total findings  9

  • [https://example.com]
      🟠 [HIGH    ] Missing header: Content-Security-Policy
      🟠 [HIGH    ] Missing header: Strict-Transport-Security
      🟡 [MEDIUM  ] Missing header: X-Frame-Options
      🟡 [MEDIUM  ] Missing header: X-Content-Type-Options
      🟡 [MEDIUM  ] Missing HSTS header
      🔵 [LOW     ] Missing header: Referrer-Policy
      🔵 [LOW     ] Missing header: Permissions-Policy
      🔵 [LOW     ] Information disclosure: Server
      ⚪ [INFO    ] Technologies detected: Cloudflare
```

---

## 🧩 Plugins

| Plugin | Checks |
|--------|--------|
| `config_files` | 50+ exposed files: `.env`, `.git/config`, `wp-config.php`, SSH keys, SQL dumps |
| `headers` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `directories` | `/admin`, `/backup`, `/.git/`, phpMyAdmin and open directory listings |
| `sql_injection` | Error-based, **boolean-blind** and **time-blind** — MySQL / PostgreSQL / MSSQL / Oracle |
| `xss` | Reflected XSS in query parameters with injection-context classification |
| `cors` | Reflected `Origin`, wildcard `*`, credentials exposure |
| `cookies` | Missing `Secure` / `HttpOnly` / `SameSite` flags |
| `http_methods` | Dangerous methods enabled: `PUT`, `DELETE`, `TRACE`, `CONNECT`, `PATCH` |
| `path_traversal` | `../../../etc/passwd`, `windows/win.ini` and encoded variants |
| `open_redirect` | `?next=`, `?redirect=`, `?url=` parameter abuse |
| `ssrf` | AWS/GCP metadata & localhost probes (response-signature based) |
| `ssl_tls` | Weak protocols (SSLv2/3, TLS 1.0/1.1), expired/expiring certs, missing HSTS |
| `tech_fingerprint` | Server / framework / CMS detection from headers, cookies & HTML |
| `subdomains` | DNS brute force + Certificate Transparency logs (crt.sh) |

> Run `webscan --list-plugins` to see them all, or pick a subset with `--plugins`.

---

## 🚀 Usage

```bash
# Single target, all plugins
webscan -t https://example.com

# Crawl first, then scan every discovered URL
webscan -t https://example.com --crawl --depth 3

# Authenticated scan (form login)
webscan -t https://example.com/dashboard \
        --login-url https://example.com/login \
        --login-data "username=admin&password=secret"

# Through a proxy (e.g. Burp) with a rotating User-Agent and rate limiting
webscan -t https://example.com --proxy http://127.0.0.1:8080 --random-agent --rate-limit 5

# Only high+ findings, write an HTML + SARIF report
webscan -t https://example.com --min-severity high -o ./reports/scan --format html sarif

# Pick specific plugins / read targets from a file
webscan -t https://example.com --plugins xss sql_injection headers
webscan -f targets.txt --format json csv
```

<details>
<summary><b>All flags</b></summary>

```
Targets
  -t URL [URL ...]       Target URL(s)
  -f FILE                File with one URL per line (# comments allowed)

Crawler
  --crawl                Spider each target before scanning
  --depth N              Max crawl depth (default: 2)
  --max-urls N           Max URLs to discover per seed (default: 200)
  --scope DOMAIN         Restrict crawl to this host
  --exclude PATTERN ...  Skip URLs containing these substrings
  --ignore-robots        Ignore robots.txt

Authentication
  --cookie STRING        Raw cookie header
  --header "K: V"        Extra header (repeatable)
  --basic-auth user:pass HTTP Basic auth
  --login-url URL        Form-login endpoint
  --login-data STRING    Form-login POST body

Network & evasion
  --proxy URL            HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)
  --user-agent STRING    Custom User-Agent
  --random-agent         Rotate through a built-in User-Agent pool
  --delay SEC            Delay before each target
  --random-delay         Randomise the delay ×0.5–×1.5
  --rate-limit N         Cap at N requests per second
  --no-verify-ssl        Skip TLS certificate verification
  --no-bruteforce        Disable DNS brute force (subdomains plugin)

Plugins & output
  --plugins NAME [...]   Plugins to run (default: all)
  --list-plugins         List plugins and exit
  -o PATH                Report base path (no extension)
  --format FMT [...]     json | md | html | sarif | csv  (default: json md)
  --min-severity LEVEL   critical | high | medium | low | info
  --no-color             Disable ANSI colour
  -v                     Verbose
  -q                     Quiet

Performance
  -c N                   Concurrent targets (default: 10)
  --timeout SEC          Per-request timeout (default: 10)
```

</details>

---

## 📊 Output formats

| Format | Flag | Use case |
|--------|------|----------|
| JSON | `--format json` | CI/CD, scripting, integrations |
| Markdown | `--format md` | Human review, GitHub PRs |
| HTML | `--format html` | Self-contained stakeholder reports |
| SARIF | `--format sarif` | GitHub Code Scanning, VS Code |
| CSV | `--format csv` | Excel, Jira, Notion |

**CI-friendly:** WebScan exits with code `1` when any CRITICAL or HIGH finding is detected.

---

## ⚙️ CI/CD

A ready-to-use workflow ships in [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml):

```yaml
name: Security Scan
on: [workflow_dispatch]
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with: { python-version: "3.12" }
      - run: pip install .
      - run: webscan -t ${{ secrets.STAGING_URL }} --min-severity high --format sarif -o report
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```

### Docker

```bash
docker build -t webscan .
docker run --rm webscan -t https://example.com

# Mount a directory to keep reports
docker run --rm -v "$(pwd)/reports:/reports" webscan \
  -t https://example.com -o /reports/scan --format json html
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
        # ... perform checks, append Finding(...) objects ...
        return findings
```

Register it in `webscan/cli.py` → `ALL_PLUGINS["my_plugin"] = MyPlugin`. Done.

---

## 🏗 Architecture

```
webscan/
├── cli.py              # Entry point, argument parsing
├── engine.py           # Async scan orchestrator (concurrency, sessions)
├── crawler.py          # Async breadth-first spider (links + forms)
├── auth.py             # Auth: cookie, header, basic, form-based login
├── net.py              # Proxy, User-Agent rotation, rate limiting
├── models.py           # Finding, Severity, ScanReport dataclasses
├── reporter.py         # JSON / MD / HTML / SARIF / CSV output
├── utils/html.py       # Dependency-free HTML link & form parser
└── plugins/
    ├── base.py         # BasePlugin ABC
    ├── headers.py
    ├── sql_injection.py
    ├── xss.py
    └── ...             # one file per plugin (14 total)
```

Runtime dependency: **`aiohttp` only**. Everything else is the Python standard library.

---

## 📦 Installation

```bash
# from source
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan && pip install .

# development install (ruff, mypy, pytest)
pip install -e ".[dev]"
```

**Requirements:** Python ≥ 3.10, `aiohttp` ≥ 3.9

---

## 🤝 Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
pip install -e ".[dev]"
ruff check webscan tests
mypy webscan
pytest -q
```

---

## ⚖️ Legal

WebScan is for **authorized security testing only**. Use it solely on systems you own or
have explicit written permission to test. Unauthorized scanning may be illegal in your
jurisdiction.

---

<div align="center">

Made with ☕ and too many CVEs

**[⭐ Star if useful](https://github.com/lutzashl290788-cell/webscan/stargazers)** · **[🐛 Report bug](https://github.com/lutzashl290788-cell/webscan/issues)** · **[💡 Request feature](https://github.com/lutzashl290788-cell/webscan/issues)**

</div>

Future Milestone: Integrating LLM-powered auditing (Claude 3.5 Sonnet) for smart false-positive reduction.
