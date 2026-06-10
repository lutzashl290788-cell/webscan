# 🔍 WebScan

**Automated CLI security auditor for web configuration vulnerabilities.**

WebScan is a modular, async Python tool that helps developers and penetration testers perform a quick first-pass security audit on web targets — detecting exposed config files, missing HTTP security headers, and accessible sensitive directories.

---

## Features

| Plugin             | What it checks |
|--------------------|----------------|
| `config_files`     | 50+ exposed files: `.env`, `.git/config`, `wp-config.php`, SSH keys, SQL dumps, … |
| `headers`          | Missing/weak security headers: CSP, HSTS, X-Frame-Options, and more |
| `directories`      | Accessible sensitive directories: `/admin`, `/backup`, `/.git/`, phpMyAdmin, … |
| `sql_injection`    | SQL injection — error-based, boolean-blind and time-blind (MySQL, PostgreSQL, MSSQL, Oracle, …) |
| `xss`              | Reflected XSS in URL query parameters with injection-context classification |
| `path_traversal`   | Path traversal / local file inclusion (`../etc/passwd`, `windows/win.ini`) |
| `open_redirect`    | Open redirects in redirect-like parameters (`next`, `url`, `redirect`, …) |
| `cors`             | CORS misconfigurations: reflected `Origin`, wildcard `*`, credentials exposure |
| `cookies`          | Cookie security flags: missing `Secure` / `HttpOnly` / `SameSite` |
| `http_methods`     | Dangerous enabled HTTP methods: `PUT`, `DELETE`, `TRACE`, `CONNECT`, `PATCH` |
| `security_txt`     | `security.txt` (RFC 9116) presence and content best practices |
| `tech_fingerprint` | Server / framework / CMS fingerprinting from headers, cookies and HTML |

- ⚡ **Async** — `aiohttp`-powered, scans dozens of targets concurrently
- 🕷️ **Crawler** — spider targets to discover URLs and forms (depth/scope/robots-aware)
- 🔐 **Authentication** — cookie, header, basic-auth and form-login support
- 🌐 **Network & evasion** — proxy, User-Agent rotation and request rate limiting
- 🧩 **Plugin architecture** — easy to extend with new check modules
- 📄 **Reports** — JSON, Markdown and a self-contained HTML report
- 🛡️ **Non-crashing** — every error is captured; the tool always exits cleanly
- 🐍 **Python 3.10+**, fully typed, PEP 8 compliant, **zero runtime deps beyond `aiohttp`**

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/lutzashl290788-cell/webscan.git
cd webscan
pip install .
```

### Development install (with linting / test tools)

```bash
pip install -e ".[dev]"
```

### Requirements

- Python ≥ 3.10
- `aiohttp` ≥ 3.9

---

## Quick Start

```bash
# Single target, all plugins, print to stdout
webscan -t https://example.com

# Multiple targets
webscan -t https://a.com https://b.com

# Targets from a file
webscan -f targets.txt

# Save reports
webscan -t https://example.com -o ./reports/scan

# Verbose: print every finding
webscan -t https://example.com -v

# Select specific plugins
webscan -t https://example.com --plugins headers config_files

# Crawl the site first, then scan every discovered URL
webscan -t https://example.com --crawl --depth 2

# Scan behind a login (form-based authentication)
webscan -t https://example.com/dashboard \
        --login-url https://example.com/login \
        --login-data "username=admin&password=secret"

# Route through a proxy with a rotating User-Agent and rate limiting
webscan -t https://example.com --proxy http://127.0.0.1:8080 --random-agent --delay 0.5

# Write an HTML report and only show high+ findings in the console
webscan -t https://example.com -o ./reports/scan --format html --min-severity high

# List available plugins
webscan --list-plugins
```

### Docker

```bash
docker build -t webscan .
docker run --rm webscan -t https://example.com
```

---

## Usage Reference

**Targets & plugins**

| Flag | Description |
|------|-------------|
| `-t URL …` | Target URL(s) |
| `-f FILE` | File with one URL per line (`#` comments supported) |
| `--plugins` | Which plugins to run (default: all) |
| `--list-plugins` | Print all available plugins and exit |

**Crawler**

| Flag | Description |
|------|-------------|
| `--crawl` | Spider each target to discover more URLs before scanning |
| `--depth N` | Maximum crawl depth from each seed (default: 2) |
| `--max-urls N` | Maximum URLs to discover per seed (default: 200) |
| `--scope DOMAIN` | Restrict crawling to this host (default: each seed's host) |
| `--exclude PATTERN …` | Skip URLs containing any of these substrings |
| `--ignore-robots` | Ignore `robots.txt` rules while crawling |

**Authentication**

| Flag | Description |
|------|-------------|
| `--cookie "k=v; …"` | Raw cookie header sent with every request |
| `--header "Name: Value"` | Extra header (repeatable) |
| `--basic-auth user:pass` | HTTP Basic auth credentials |
| `--login-url URL` + `--login-data "u=a&p=b"` | Form login to capture a session |

**Network & evasion**

| Flag | Description |
|------|-------------|
| `--proxy URL` | Route requests through an HTTP/SOCKS proxy |
| `--user-agent STR` | Override the User-Agent header |
| `--random-agent` | Rotate through a pool of browser User-Agents |
| `--delay SEC` | Wait before each target (rate limiting) |

**Output & performance**

| Flag | Description |
|------|-------------|
| `-o PATH` | Base path for report files (without extension) |
| `--format json md html` | Report format(s) — any of `json`, `md`, `html` (default: `json md`) |
| `--min-severity LEVEL` | Only show findings at or above this severity in the console |
| `--no-color` | Disable ANSI colour in the console summary |
| `-v` | Verbose: print every finding to stdout |
| `-q` | Quiet: suppress all stdout except errors |
| `-c N` | Concurrency — max simultaneous targets (default: 10) |
| `--timeout SEC` | Per-request timeout in seconds (default: 10) |

---

## Target File Format

```
# targets.txt
https://example.com
https://staging.example.com
# disabled: https://old.example.com
http://internal-app:8080
```

---

## Output

### JSON (`-o report` → `report.json`)

```json
{
  "scan_started": "2025-01-15T10:00:00+00:00",
  "scan_finished": "2025-01-15T10:00:42+00:00",
  "total_findings": 7,
  "targets": [
    {
      "target": "https://example.com",
      "scanned_at": "2025-01-15T10:00:05+00:00",
      "findings": [
        {
          "plugin": "config_files",
          "title": "Exposed file: /.env",
          "severity": "critical",
          "description": "...",
          "url": "https://example.com/.env",
          "evidence": { "http_status": 200, "content_type": "text/plain" },
          "remediation": "..."
        }
      ],
      "errors": []
    }
  ]
}
```

### Markdown (`-o report` → `report.md`)

A human-readable document with a summary table and per-finding sections including severity badges, evidence, and remediation guidance.

### HTML (`-o report --format html` → `report.html`)

A self-contained, dark-themed report with inline CSS and severity colour-coding — no external assets, opens offline in any browser.

---

## Severity Levels

| Badge | Level | Typical examples |
|-------|-------|-----------------|
| 🔴 CRITICAL | Immediate risk of credential theft or RCE | `.env` exposed, SSH private key accessible |
| 🟠 HIGH | Serious misconfig, likely exploitable | `.git/config` public, missing HSTS/CSP |
| 🟡 MEDIUM | Defence-in-depth gap | Missing X-Frame-Options, accessible upload dir |
| 🔵 LOW | Informational / minor hardening | Server header disclosure, missing Referrer-Policy |
| ⚪ INFO | Neutral observation | — |

WebScan exits with **code 1** when any CRITICAL or HIGH finding is detected (useful for CI pipelines).

---

## Extending WebScan: Writing a Plugin

1. Create `webscan/plugins/my_plugin.py`:

```python
from __future__ import annotations
import aiohttp
from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "What it does in one line"

    async def run(self, target: str, session: aiohttp.ClientSession) -> list[Finding]:
        findings: list[Finding] = []
        # ... perform checks ...
        return findings
```

2. Register it in `webscan/cli.py`:

```python
from webscan.plugins.my_plugin import MyPlugin

ALL_PLUGINS = {
    ...
    "my_plugin": MyPlugin,
}
```

That's it — `webscan --plugins my_plugin -t https://example.com` will run it.

---

## ⚠️ Legal Notice

WebScan is intended for use **only** on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.

---

## License

MIT © WebScan contributors
