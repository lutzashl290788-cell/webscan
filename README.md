# 🔍 WebScan

**Automated CLI security auditor for web configuration vulnerabilities.**

WebScan is a modular, async Python tool that helps developers and penetration testers perform a quick first-pass security audit on web targets — detecting exposed config files, missing HTTP security headers, and accessible sensitive directories.

---

## Features

| Plugin          | What it checks |
|-----------------|----------------|
| `config_files`  | 50+ exposed files: `.env`, `.git/config`, `wp-config.php`, SSH keys, SQL dumps, … |
| `headers`       | Missing/weak security headers: CSP, HSTS, X-Frame-Options, and more |
| `directories`   | Accessible sensitive directories: `/admin`, `/backup`, `/.git/`, phpMyAdmin, … |

- ⚡ **Async** — `aiohttp`-powered, scans dozens of targets concurrently
- 🧩 **Plugin architecture** — easy to extend with new check modules
- 📄 **Reports** — JSON (machine-readable) + Markdown (human-readable)
- 🛡️ **Non-crashing** — every error is captured; the tool always exits cleanly
- 🐍 **Python 3.10+**, fully typed, PEP 8 compliant

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

# List available plugins
webscan --list-plugins
```

---

## Usage Reference

```
webscan [-h] [-t URL [URL ...]] [-f FILE]
        [--plugins NAME [NAME ...]] [--list-plugins]
        [-o PATH] [--format FMT [FMT ...]]
        [-v] [-q]
        [-c N] [--timeout SEC]
```

| Flag | Description |
|------|-------------|
| `-t URL …` | Target URL(s) |
| `-f FILE` | File with one URL per line (`#` comments supported) |
| `--plugins` | Which plugins to run (default: all) |
| `--list-plugins` | Print all available plugins and exit |
| `-o PATH` | Base path for report files (without extension) |
| `--format json md` | Report format(s) — `json`, `md`, or both (default: both) |
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
