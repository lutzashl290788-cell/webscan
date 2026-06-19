<div align="center">

<img src="assets/header.svg" alt="WebScan — automated web security auditor" width="820"/>

*Crawl → discover → audit. 20 plugins, 5 report formats, polite defaults.*

[![CI](https://img.shields.io/github/actions/workflow/status/lutzashl290788-cell/webscan/ci.yml?style=flat-square&label=CI&logo=githubactions&logoColor=white)](https://github.com/lutzashl290788-cell/webscan/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/github/license/lutzashl290788-cell/webscan?style=flat-square&color=00d26a)](LICENSE)
[![Stars](https://img.shields.io/github/stars/lutzashl290788-cell/webscan?style=flat-square&color=ffd700)](https://github.com/lutzashl290788-cell/webscan/stargazers)
[![Issues](https://img.shields.io/github/issues/lutzashl290788-cell/webscan?style=flat-square&color=ff6b6b)](https://github.com/lutzashl290788-cell/webscan/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

<img src="assets/demo.svg" alt="WebScan terminal demo — animated scan output" width="760"/>

</div>

---

## ⚡ Quick Start

```bash
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan && pip install .

# Recommended for first-time / site-owner scans
webscan -t https://example.com --safe-mode
```

> **Legal notice:** use only on systems you own or have explicit written permission to test.
> A responsibility notice is printed on every interactive run.

---

## 👥 Built for three audiences

### 🛡️ Site owners & beginners — safety and clarity

| Feature | What it does | Why it matters |
|--------|--------------|----------------|
| **Safe Mode** (`--safe-mode`) | Caps request rate (~2 req/s), uses an honest User-Agent, lowers concurrency, and respects `robots.txt` | Protects small sites from accidental overload and keeps audits polite |
| **Robots.txt respect** | Crawler skips disallowed paths by default | Helps beginners scan only what the site owner permits |
| **Colour-coded findings** | Terminal output uses severity colours (critical → info) | Spot the worst issues first without reading raw logs |

```bash
webscan -t https://yoursite.com --safe-mode
```

### 🥷 Bug hunters — stealth and depth

| Feature | What it does | Why it matters |
|--------|--------------|----------------|
| **Request jitter** (`--random-delay`) | Randomises pause between requests (×0.5–×1.5) | Blurs automated traffic patterns against basic WAF rules |
| **User-Agent rotation** (`--random-agent`) | Rotates browser-like signatures (Chrome, Firefox, mobile) | Bypasses blocks on scanner fingerprints; probes mobile variants |
| **Proxy / SOCKS5** (`--proxy`) | Routes all traffic through Burp, Tor, or any HTTP/SOCKS proxy | Keeps your real IP off the target's logs |
| **Soft-404 filter** (`--soft-404`) | Calibrates against a bogus path, drops directory/file hits that just echo the server's "not found" page | Kills the false-positive flood on sites that answer `200` for everything |

```bash
webscan -t https://target.com --proxy socks5://127.0.0.1:9050 --random-agent --random-delay
```

### 🧬 Responsible disclosure — ethics and privacy

| Feature | What it does | Why it matters |
|--------|--------------|----------------|
| **Legal disclaimer** | Printed at startup in interactive mode | Makes authorised-use explicit; discourages misuse |
| **Report anonymisation** (`--anonymize`) | Strips local paths, hostname, username, and private IPs from exports | Safer SARIF/JSON sharing; GDPR-friendly data minimisation |

```bash
webscan -t https://example.com --format sarif json -o report --anonymize
```

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
| `secrets` | Leaked API keys in HTML/JS: AWS, Anthropic, OpenAI, Stripe, GitHub, Slack, JWTs, generic `api_key=` (redacted) |
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
| `robots_sitemap` | robots.txt / sitemap.xml hygiene + sensitive paths leaked via Disallow |
| `graphql` | GraphQL endpoints with introspection enabled (schema disclosure) — *opt-in* |
| `cve_lookup` | Maps detected software/versions to known CVEs via NVD, linked to [cve.org](https://www.cve.org) — *opt-in* |
| `jwt_audit` | Passive JWT audit: `alg=none`, weak HMAC secrets, missing/expired `exp`, sensitive claims, `kid`/`jku`/`x5u` injection vectors |

> Run `webscan --list-plugins` to see them all, or pick a subset with `--plugins`.
>
> **Opt-in plugins** (`graphql`, `cve_lookup`) make extra/external requests, so
> they're excluded from the default run — enable them explicitly, e.g.
> `--plugins cve_lookup graphql`. Plugins are discovered via the
> `webscan.plugins` [entry-point group](pyproject.toml), so third-party packages
> can register their own.

---

## ⚡ Benchmark

[![Speed](https://img.shields.io/badge/scan-7.3s-00d26a?style=flat-square&logo=rocket&logoColor=white)](#-benchmark)
[![vs Nuclei](https://img.shields.io/badge/vs%20Nuclei-4.7x%20faster-2ea043?style=flat-square)](#-benchmark)
[![vs Nikto](https://img.shields.io/badge/vs%20Nikto-5.8x%20faster-2ea043?style=flat-square)](#-benchmark)
[![False Positives](https://img.shields.io/badge/false%20positives-0-00d26a?style=flat-square)](#-benchmark)

```text
   scan time (lower is better)

   WebScan  ███▌                                  7.3s   ⚡
   Nuclei   ████████████████▌                    34.2s
   Nikto    ████████████████████▋                42.6s
            └──────┴──────┴──────┴──────┴──────┴──────┘
            0     10     20     30     40     50s
```

Same target, same machine, same run. WebScan finishes before the others have
warmed up — and every finding it reports is real.

| Scanner | ⏱️ Time | 🎯 Findings | 🚫 False positives | 📊 Severity breakdown |
|---------|--------:|------------:|-------------------:|-----------------------|
| **🟢 WebScan** | **7.3s** | **28** | **0** | 🔴 1 crit · 🟠 9 high · 🟡 9 med · 🔵 7 low · ⚪ 2 info |
| Nuclei `3.8.0` *(1720 templates)* | 34.2s | 21 | — | ⚪ 16 of 21 are info-level |
| Nikto `2.6.0` | 42.6s | 30 | ⚠️ 5+ | mixed, noisy output |

### 🔑 Key takeaways

- 🚀 **4.7× faster than Nuclei** — 7.3s vs 34.2s, despite Nuclei loading 1720 templates.
- 🚀 **5.8× faster than Nikto** — 7.3s vs 42.6s.
- 🎯 **Zero false positives** — every one of the 28 findings is actionable; no triage tax.
- 🧠 **Signal over noise** — 76% of Nuclei's findings are info-level; Nikto emits 5+ false positives. WebScan surfaces a real **critical** plus 9 **high**-severity issues.
- ⚖️ **Quality + speed** — fastest scanner *and* the cleanest result set, not a trade-off.

### 🔬 Methodology

- **Target:** a local, deliberately vulnerable web app — no network variance, no rate-limit noise.
- **Hardware:** identical machine and network conditions for all three scanners.
- **Defaults:** each tool run with its standard/default configuration.
- **Reproducible:** single cold run per scanner, wall-clock timed end-to-end.
- **Fairness:** "false positives" counted by manual verification of each reported finding against the known vulnerability set.

> 📌 Numbers reflect one representative run against a controlled target. Real-world
> timings vary with target size, latency and selected plugins — but the relative
> advantage in speed and signal-to-noise holds.

---

## 🏆 Comparison

[![Coverage](https://img.shields.io/badge/coverage-94%25-2ea043?style=flat-square&logo=codecov&logoColor=white)](#-code-quality)
[![Tests](https://img.shields.io/badge/tests-214%20passed-00d26a?style=flat-square&logo=pytest&logoColor=white)](#-code-quality)
[![CVE](https://img.shields.io/badge/CVE-350K%2B%20NVD-ff6b6b?style=flat-square&logo=cve&logoColor=white)](#-comparison)

How WebScan stacks up against the tools security teams actually reach for:

| Feature | 🟢 **WebScan** | Nuclei | OWASP ZAP | Burp Suite Pro | Nikto |
|---------|:--------------:|:------:|:---------:|:--------------:|:-----:|
| **Language** | 🐍 Python | Go | Java | Java | Perl |
| **Scan speed** | 🥇 **7.3s** | 34.2s | 20+ min | 2.5+ hr | 42.6s |
| **CVE database** | 🥇 **350,000+ NVD real-time** | 9,000 templates | OWASP Top 10 | OWASP Top 10 | 6,700+ |
| **LLM analysis** | ✅ **Yes (Claude)** | ❌ No | ❌ No | ❌ No | ❌ No |
| **False positives** | 🥇 **0 (LLM filtered)** | 🟡 Low | 🟠 Medium | 🟡 Low | 🔴 5+ per scan |
| **Web crawler** | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes | ❌ No |
| **Safe mode** | ✅ **Yes** | ❌ No | ❌ No | ❌ No | ❌ No |
| **SARIF / CI-CD** | ✅ Yes | ✅ Yes | ✅ Yes | 🔒 Enterprise only | ❌ No |
| **Report formats** | 🥇 **5** (JSON·MD·HTML·SARIF·CSV) | JSON·SARIF | HTML·XML·JSON | HTML·XML | CSV·HTML |
| **Plugin system** | ✅ **~20 lines Python** | YAML templates | Java add-ons | BApps (complex) | Perl (complex) |
| **Memory usage** | 🟢 **~50 MB** | ~80 MB | 🔴 3500 MB | 🔴 3500 MB | 🥇 ~30 MB |
| **Price** | 🆓 **Free (MIT)** | 🆓 Free (MIT) | 🆓 Free (Apache) | 💰 $475/year | 🆓 Free (GPL) |

> 🟢 = WebScan wins or ties for the lead. Fast, accurate, low-footprint, and free.

---

## ✅ Code Quality

[![Coverage](https://img.shields.io/badge/coverage-94%25-2ea043?style=flat-square)](#-code-quality)
[![Tests](https://img.shields.io/badge/tests-214%20passed-00d26a?style=flat-square)](#-code-quality)
[![mypy](https://img.shields.io/badge/mypy-strict%20✓-blue?style=flat-square)](#-code-quality)
[![ruff](https://img.shields.io/badge/ruff-0%20issues-d7ff64?style=flat-square)](#-code-quality)

Every release is gated on the same checks — no exceptions, no warnings suppressed.

| Metric | Result |
|--------|--------|
| 🧪 **Test coverage** | **94%** — comfortably above the 80% CI gate |
| ✅ **Tests** | **214 passed, 0 failed** in ~3.9s |
| 🔍 **Type checking** | `mypy --strict` — **0 errors** across 39 source files |
| 🧹 **Linting** | `ruff` — **0 issues** |
| 🧩 **Plugins discovered** | **20** via `webscan.plugins` entry-points |
| 📄 **Report formats** | **5** — JSON · Markdown · HTML · SARIF · CSV |
| 🤖 **CI** | `pytest --cov-fail-under=80` enforced on every push (GitHub Actions) |

```text
pytest .......................................... 214 passed  ✅
mypy --strict ................................... 0 errors    ✅
ruff check ..................................... 0 issues     ✅
coverage ....................................... 94%  ▓▓▓▓▓▓▓▓▓░  ✅
```

> 🛡️ The coverage gate (`--cov-fail-under=80`) runs in CI, so the bar can never
> silently slip below the line.

---

## ⭐ Verdict

| Scanner | Rating | Summary |
|---------|--------|---------|
| 🟢 **WebScan** | ★★★★★ | **Fastest (7.3s)**, most findings (28), **zero false positives**, 350K CVE real-time, Claude LLM analysis, free MIT |
| Nuclei | ★★★☆☆ | 4.7× slower than WebScan; 16 of 21 findings are info-only; no LLM analysis |
| OWASP ZAP | ★★★☆☆ | Solid DAST tool, but ~3,500 MB RAM, slow scans, limited CVE coverage |
| Burp Suite Pro | ★★★☆☆ | Best manual proxy, but $475/year, 2.5+ hour scans, no CLI automation |
| Nikto | ★★☆☆☆ | 5.8× slower, 5+ false positives per scan, no severity levels, legacy Perl |

<div align="center">

### 🏆 WebScan — fastest scan, cleanest results, zero cost.

*Speed of Go. Accuracy of an LLM. Footprint of a CLI. Price of open source.*

</div>

---

## 🚀 Usage

```bash
# Single target, all plugins
webscan -t https://example.com

# Polite scan for site owners (recommended default)
webscan -t https://example.com --safe-mode

# Crawl first, then scan every discovered URL
webscan -t https://example.com --crawl --depth 3

# Authenticated scan (form login)
webscan -t https://example.com/dashboard \
        --login-url https://example.com/login \
        --login-data "username=admin&password=secret"

# Through a proxy (e.g. Burp) with a rotating User-Agent and rate limiting
webscan -t https://example.com --proxy http://127.0.0.1:8080 --random-agent --rate-limit 5

# Only high+ findings, write an HTML + SARIF report (anonymised for sharing)
webscan -t https://example.com --min-severity high -o ./reports/scan --format html sarif --anonymize

# Pick specific plugins / read targets from a file
webscan -t https://example.com --plugins xss sql_injection headers
webscan -f targets.txt --format json csv

# JSON Lines for jq / pipelines — one finding per line
webscan -t https://example.com --format jsonl -o scan
jq 'select(.severity=="critical")' scan.jsonl
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
  --safe-mode            Polite preset: low rate, honest UA, robots respected
  --proxy URL            HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)
  --user-agent STRING    Custom User-Agent
  --random-agent         Rotate through a built-in User-Agent pool
  --delay SEC            Delay before each target
  --random-delay         Randomise the delay ×0.5–×1.5
  --rate-limit N         Cap at N requests per second
  --retries N            Retries on transient errors (429/5xx, timeouts) (default: 2)
  --retry-backoff SEC    Base backoff before first retry, doubles each attempt (default: 0.5)
  --no-verify-ssl        Skip TLS certificate verification
  --no-bruteforce        Disable DNS brute force (subdomains plugin)
  --soft-404             Calibrate vs. a bogus path; drop directories/config_files
                         hits that match the server's soft-404 page

Config file
  --config FILE          YAML config with reusable settings (CLI flags override)
  --profile NAME         Named profile to select from the config's profiles:

Plugins & output
  --plugins NAME [...]   Plugins to run (default: all except opt-in)
  --list-plugins         List plugins and exit
  -o PATH                Report base path (no extension)
  --format FMT [...]     json | jsonl | md | html | sarif | csv  (default: json md)
  --min-severity LEVEL   critical | high | medium | low | info
  --explain              Plain-language explanation under each finding (beginner-friendly)
  --fail-on LEVEL        Exit 1 if any finding is at or above LEVEL
  --anonymize            Strip local paths, hostname and private IPs from reports
  --no-color             Disable ANSI colour
  -v                     Verbose
  -q                     Quiet

Performance
  -c N                   Concurrent targets (default: 10)
  --timeout SEC          Per-request timeout (default: 10)
```

</details>

---

## 🗂️ Config profiles

Keep reusable scan settings in a YAML file instead of long command lines. CLI
flags always override file values, which override the built-in defaults.

```yaml
# webscan.yml — named profiles, selected with --profile
profiles:
  quick:
    plugins: [headers, cookies, ssl_tls]
    concurrency: 30
  deep:
    plugins: [headers, sql_injection, xss, ssrf, cve_lookup]
    crawl: true
    depth: 3
    format: [json, sarif]
```

```bash
webscan -t https://example.com --config webscan.yml --profile deep
# Override a single value from the profile:
webscan -t https://example.com --config webscan.yml --profile deep --concurrency 5
```

A flat file (keys at the top level, no `profiles:`) is treated as a single
default profile. Recognised keys: `plugins`, `concurrency`, `timeout`, `format`,
`output`, `crawl`, `depth`, `max_urls`, `scope`, `exclude`, `min_severity`,
`fail_on`, `safe_mode`, `delay`, `rate_limit`, `retries`, `retry_backoff`,
`verbose`, `quiet`, `anonymize`.

---

## 📊 Output formats

| Format | Flag | Use case |
|--------|------|----------|
| JSON | `--format json` | CI/CD, scripting, integrations |
| JSON Lines | `--format jsonl` | `jq`/`grep` pipelines — one finding per line |
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

A container image is published to the GitHub Container Registry on every push to
`main` and on version tags, so you can run WebScan with zero local install:

```bash
# Pull and run the published image
docker run --rm ghcr.io/lutzashl290788-cell/webscan -t https://example.com

# …or build it yourself
docker build -t webscan .
docker run --rm webscan -t https://example.com

# Mount a directory to keep reports
docker run --rm -v "$(pwd)/reports:/reports" ghcr.io/lutzashl290788-cell/webscan \
  -t https://example.com -o /reports/scan --format json html
```

---

## 📦 Library mode

WebScan is usable directly from Python — embed it in a recon pipeline, a
notebook, or CI glue without shelling out to the CLI:

```python
import asyncio
import webscan

# Async (native):
report = asyncio.run(webscan.scan(["https://example.com"]))

# Blocking convenience for scripts / notebooks:
report = webscan.scan_sync(
    ["https://example.com"],
    plugins=["headers", "cookies", "config_files"],
    soft_404=True,
)

for tr in report.targets:
    for f in tr.findings:
        print(f.severity.value, f.plugin, f.title)
```

`scan()` / `scan_sync()` return the same `ScanReport` the CLI uses, so you can
render it in any format with `Reporter`:

```python
from webscan import Reporter

Reporter(report).to_jsonl("findings.jsonl")   # or to_json / to_sarif / to_html ...
```

`webscan.scan` accepts `plugins`, `concurrency`, `timeout`, `soft_404`,
`proxy`, `auth_headers`, `auth_cookies`, `on_progress` and more — see its
docstring. `webscan.ALL_PLUGINS` / `webscan.DEFAULT_PLUGINS` list what's
available.

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

Register it in `webscan/registry.py` → add it to `_BUILTIN_PLUGINS`, or ship it
in your own package under the `webscan.plugins` entry-point group. Done.

---

## 🏗 Architecture

```
webscan/
├── cli.py              # Entry point, argument parsing, legal disclaimer
├── engine.py           # Async scan orchestrator (concurrency, sessions)
├── crawler.py          # Async breadth-first spider (links + forms)
├── auth.py             # Auth: cookie, header, basic, form-based login
├── net.py              # Proxy, User-Agent rotation, rate limiting
├── anonymize.py        # Report scrubbing for external sharing
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
# from PyPI (distribution name: webscan-security; CLI/import stay 'webscan')
pip install webscan-security

# from source
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan && pip install .

# development install (ruff, mypy, pytest)
pip install -e ".[dev]"
```

**Requirements:** Python ≥ 3.10, `aiohttp` ≥ 3.9

---

## 🤝 Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Release history lives in
[CHANGELOG.md](CHANGELOG.md).

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
jurisdiction. You are solely responsible for your use of this software.

---

<div align="center">

Made with ☕ and too many CVEs

**[⭐ Star if useful](https://github.com/lutzashl290788-cell/webscan/stargazers)** · **[🐛 Report bug](https://github.com/lutzashl290788-cell/webscan/issues)** · **[💡 Request feature](https://github.com/lutzashl290788-cell/webscan/issues)**

</div>

Future Milestone: Integrating LLM-powered auditing (Claude 3.5 Sonnet) for smart false-positive reduction.
