<div align="center">

<img src="assets/header.svg" alt="WebScan - automated web security auditor" width="820" />

# WebScan

**Discover. Verify. Report.**

Content-verified web security auditing for teams who need useful signal,
repeatable runs, and reports that fit the rest of their workflow.

[![CI](https://img.shields.io/github/actions/workflow/status/lutzashl290788-cell/webscan/ci.yml?style=flat-square&label=CI&logo=githubactions&logoColor=white)](https://github.com/lutzashl290788-cell/webscan/actions)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/github/license/lutzashl290788-cell/webscan?style=flat-square&color=00d26a)](LICENSE)
[![Plugins](https://img.shields.io/badge/plugins-41-2f81f7?style=flat-square)](#plugin-catalog)
[![Formats](https://img.shields.io/badge/report%20formats-6-8250df?style=flat-square)](#reports)

<img src="assets/demo.svg" alt="WebScan terminal scan summary" width="760" />

</div>

> [!WARNING]
> Scan only systems you own or have explicit written permission to test. You are
> responsible for authorization, scope, rate limits, and the impact of every scan.

## Contents

- [Why WebScan](#why-webscan)
- [Quick start](#quick-start)
- [Choose your workflow](#choose-your-workflow)
- [How a scan works](#how-a-scan-works)
- [Plugin catalog](#plugin-catalog)
- [Reports](#reports)
- [Performance snapshot](#performance-snapshot)
- [CLI reference](#cli-reference)
- [Configuration profiles](#configuration-profiles)
- [CI/CD](#cicd)
- [Python API](#python-api)
- [Architecture](#architecture)
- [Development](#development)
- [Legal](#legal)

## Why WebScan

WebScan is a focused asynchronous scanner for web configuration and application
security checks. It combines passive inspection with explicitly enabled active
probes, then verifies findings against response content before reporting them.

| Principle | What you get |
|---|---|
| **Signal over noise** | `firm`, `tentative`, and `informational` confidence tags plus soft-404 and content checks |
| **Safe by default** | `--safe-mode` lowers concurrency, caps request rate, respects `robots.txt`, and uses an honest User-Agent |
| **Built for review** | Human-readable terminal output, plain-language `--explain`, evidence, and remediation on findings |
| **Automation ready** | JSON, JSONL, Markdown, HTML, SARIF, CSV, risk gates, report diffing, and webhooks |
| **Extensible** | Built-in entry points and a small `BasePlugin` contract for third-party checks |

## Quick start

### Install from PyPI

```bash
python -m pip install webscan-security
```

### Run a first, polite audit

```bash
webscan -t https://example.com --safe-mode --explain
```

### Save a reviewable report

```bash
webscan -t https://example.com \
  --safe-mode \
  --format json html md \
  -o reports/example
```

This writes `reports/example.json`, `reports/example.html`, and
`reports/example.md`. Reports are self-contained where possible and can be
shared without a WebScan installation.

### Choose a built-in preset

```bash
webscan -t https://example.com --preset quick
webscan -t https://example.com --preset safe
webscan -t https://example.com --preset full
webscan -t https://example.com --preset active
```

| Preset | Use case |
|---|---|
| `quick` | Fast, high-confidence review of actionable findings. |
| `safe` | Polite crawl with soft-404 handling and firm findings only. |
| `full` | Safe crawl plus DNS, technology, and robots/sitemap reconnaissance. |
| `active` | Explicitly enables the heavier active checks for authorised testing. |

Presets cannot be combined with `--config`; use a YAML profile when a team
needs a custom, version-controlled configuration.

### Install from source

```bash
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan
python -m pip install .
```

Optional extras:

```bash
python -m pip install 'webscan-security[ai]'    # AI triage and summaries
python -m pip install 'webscan-security[serve]' # local HTTP backend
python -m pip install 'webscan-security[dev]'   # test and lint tooling
```

## Choose your workflow

| You need to... | Start here | Result |
|---|---|---|
| Baseline an owned site | `webscan -t https://example.com --safe-mode` | Terminal summary |
| Find routes before auditing | `webscan -t https://example.com --crawl --depth 3` | Crawl + scan of discovered URLs |
| Review only actionable signal | `webscan -t https://example.com --min-severity high --min-confidence firm` | High-confidence high-impact findings |
| Scan an authenticated area | `--cookie`, `--header`, `--basic-auth`, or `--login-url` | Session-aware checks |
| Compare two deployments | `webscan diff baseline.json current.json --fail-on-new` | New, fixed, and changed findings |
| Gate a pull request | `--format sarif -o report --fail-on-risk 70` | SARIF artifact + non-zero exit code |
| Share results safely | `--format html md --anonymize` | Redacted offline reports |
| Browse scan history locally | `webscan serve` | Dashboard at `http://127.0.0.1:8000` |

### Local dashboard

Install the optional serving dependencies and start the local dashboard:

```bash
python -m pip install 'webscan-security[serve]'
webscan serve
```

Open `http://127.0.0.1:8000` to run a scan, revisit previous scans, and filter
findings by severity, confidence, plugin, or free-text query. History is stored
in `~/.webscan/history.db` and never uploaded. Choose another location when
needed with `--history-db /path/to/history.db` or `WEBSCAN_HISTORY_DB`.

## How a scan works

```text
targets / file
      |
      v
normalize + deduplicate ---- optional crawl ----> discovered URLs
      |
      v
async engine  ---> passive plugins  ---> active plugins (selected / opt-in)
      |
      v
content verification + confidence + severity
      |
      +--> terminal summary
      +--> JSON / JSONL / Markdown / HTML / SARIF / CSV
      +--> risk score / compliance / diff / webhook
```

The default run excludes plugins that make extra external requests or may
mutate state. See the opt-in list in the catalog before enabling them.

## Plugin catalog

Run `webscan --list-plugins` for descriptions from the installed registry.

### Passive checks

`headers` · `secrets` · `cors` · `cookies` · `ssl_tls` · `security_txt` ·
`tech_fingerprint` · `robots_sitemap` · `jwt_audit` · `csrf` · `clickjacking` ·
`verbose_errors` · `prototype_pollution` · `dns_security` · `csp_analyzer` ·
`waf_detect` · `websocket_security`

These inspect responses, certificates, DNS, HTML, JavaScript, cookies, and
headers without sending exploit payloads.

### Active checks

| Plugin | Coverage |
|---|---|
| `config_files` | Exposed `.env`, `.git`, backups, keys, dumps, and common config files |
| `directories` | Admin panels, debug paths, open listings, and sensitive directories |
| `sql_injection` | Error-, boolean-blind-, and time-blind SQLi variants |
| `xss` | Reflected query parameters with injection-context classification |
| `path_traversal` / `lfi_rfi` | Unix/Windows traversal and PHP wrapper probes, content verified |
| `open_redirect` | Redirect parameter payload variants and `Location` host validation |
| `ssrf` | Cloud metadata and localhost response signatures |
| `http_methods` | Dangerous `PUT`, `DELETE`, `TRACE`, `CONNECT`, and `PATCH` methods |
| `subdomains` | Certificate Transparency and optional DNS brute force |
| `graphql` / `graphql_depth` | Introspection, depth abuse, and field suggestion disclosure |
| `xxe` | XML entity probes with per-scan markers |
| `idor` | API object-ID variations with similarity and auth-error suppression |
| `cache_poisoning` / `host_header_injection` | Host and forwarding header reflection/poisoning |
| `ssti` | Jinja2, Twig, FreeMarker, ERB, and Smarty syntax variants |
| `backup_files` | Source-verified `.bak`, `.old`, `.orig`, `~`, and `.save` files |
| `mass_assignment` | API role/property injection (opt-in) |
| `file_upload` | Harmless upload and predicted URL accessibility (opt-in) |
| `race_condition` | Concurrent request success comparison (opt-in) |
| `request_smuggling` | CL.TE and TE.CL timeout/marker probes (opt-in) |
| `web_cache_deception` | Dynamic URLs with static extensions and sensitive response checks |
| `cve_lookup` | Detected software/version mapping to NVD CVEs (opt-in, external lookup) |

> **Opt-in:** `graphql`, `cve_lookup`, `mass_assignment`, `race_condition`, and
> `request_smuggling` are excluded from the default run. Enable deliberately:
> `webscan -t https://example.com --plugins graphql cve_lookup`.

### Confidence levels

| Level | Meaning |
|---|---|
| `firm` | Directly observed or proven by a content/evidence check |
| `tentative` | Strong heuristic that needs manual confirmation |
| `informational` | Best-practice note or manual-review signal |

Use `--min-confidence firm` to keep only directly verified findings.

## Reports

| Format | Example | Best for |
|---|---|---|
| JSON | `--format json` | APIs, archives, custom tooling |
| JSONL | `--format jsonl` | `jq`, streaming, line-oriented pipelines |
| Markdown | `--format md` | Pull requests and human review |
| HTML | `--format html` | Offline stakeholder reports |
| SARIF | `--format sarif` | GitHub Code Scanning and IDE integrations |
| CSV | `--format csv` | Excel, Jira, and data imports |

Useful report workflows:

```bash
# One finding per line
webscan -t https://example.com --format jsonl -o findings
jq 'select(.severity == "critical")' findings.jsonl

# Redact local paths, host/user data, and private IPs before sharing
webscan -t https://example.com --format html sarif -o public-report --anonymize

# Risk score and OWASP Top 10 mapping
webscan -t https://example.com --risk-score --compliance
```

## Performance snapshot

The repository benchmark compares a cold, single-target Safe Mode run against
other general-purpose scanners. Treat these figures as a reference point, not a
promise for every network or target.

| Scanner | Time | Findings | False positives | Coverage |
|---|---:|---:|---:|---:|
| **WebScan 2.8** | **7.1s** | **16** | **0** | **41 plugins** |
| Nuclei 3.8 | 34.2s | 21 | not measured | template-based |
| Nikto 2.6 | 42.6s | 30 | 5+ observed | legacy checks |

Benchmark target: `httpbin.org`, 41 plugins, Safe Mode, one cold run. Run
`python benchmarks/run_benchmark.py --help` for the local benchmark options.

## CLI reference

```text
Targets
  -t, --target URL [URL ...]     One or more target URLs
  -f, --file FILE                One URL per line (# comments allowed)

Discovery
  --crawl                        Crawl before scanning
  --depth N                      Maximum crawl depth (default: 2)
  --max-urls N                   URL cap per seed (default: 200)
  --scope DOMAIN                 Restrict crawl to a host
  --exclude PATTERN ...          Skip matching URLs
  --ignore-robots                Ignore robots.txt rules

Authentication
  --cookie STRING                Raw Cookie header
  --header NAME:VALUE            Repeatable extra header
  --basic-auth USER:PASS         HTTP Basic credentials
  --login-url URL                Form login endpoint
  --login-data STRING            URL-encoded login body

Network and safety
  --safe-mode                    Polite rate, honest UA, lower concurrency, robots respected
  --stealth                      UA rotation, jitter, concurrency 1, spoofed forwarding headers
  --proxy URL                    HTTP or SOCKS5 proxy
  --user-agent STRING            Override User-Agent
  --random-agent                 Rotate browser-like User-Agents
  --delay SEC / --random-delay   Add fixed or jittered delays
  --rate-limit N                 Cap requests per second
  --retries N / --retry-backoff  Retry transient errors with exponential backoff
  --strict-ssl                   Enforce certificate verification
  --soft-404                    Calibrate and suppress soft-404 false positives

Plugins and output
  --plugins NAME [...]           Select plugins (default: all except opt-in)
  --list-plugins                 Print the registry and exit
  -o, --output PATH              Report base path
  --format FORMAT [...]           json | jsonl | md | html | sarif | csv
  --min-severity LEVEL           critical | high | medium | low | info
  --min-confidence LEVEL         firm | tentative | informational
  --explain                      Add plain-language explanations
  --anonymize                    Redact sensitive local data in exports
  --fail-on LEVEL                Exit 1 at or above severity
  --fail-on-risk N               Exit 1 when score is below N
  --risk-score                   Print the 0-100 score and A-F grade
  --compliance                   Map findings to OWASP Top 10 2021
  --suggest-fixes                Print copy-paste remediation suggestions
  --webhook-url URL              Send a Slack/Discord/Teams/HTTP summary
  --no-color / -q / -v           Disable colour, quiet mode, or verbose mode
```

Use `webscan --help` for the complete, version-specific reference.

## Configuration profiles

Keep reusable settings in YAML. Explicit CLI flags override profile values.

```yaml
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
webscan -t https://example.com --config webscan.yml --profile deep --concurrency 5
```

## CI/CD

WebScan exits with code `1` for CRITICAL/HIGH findings by default. Add a risk
threshold or `--fail-on-new` to turn security regressions into pipeline failures.

```yaml
name: WebScan
on: [workflow_dispatch]
permissions:
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with: { python-version: "3.14" }
      - run: pip install .
      - run: webscan -t "${{ secrets.STAGING_URL }}" --safe-mode --min-severity high --format sarif -o report
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: report.sarif }
```

Docker is also supported:

```bash
docker run --rm ghcr.io/lutzashl290788-cell/webscan -t https://example.com
docker run --rm -v "$(pwd)/reports:/reports" ghcr.io/lutzashl290788-cell/webscan \
  -t https://example.com -o /reports/scan --format json html
```

## Python API

```python
import asyncio
import webscan

report = asyncio.run(webscan.scan(
    ["https://example.com"],
    plugins=["headers", "cookies", "config_files"],
    soft_404=True,
))

for target in report.targets:
    for finding in target.findings:
        print(finding.severity.value, finding.confidence.value, finding.title)
```

The same `ScanReport` can be rendered with `Reporter(report).to_json()`,
`.to_jsonl()`, `.to_markdown()`, `.to_html()`, `.to_sarif()`, or `.to_csv()`.

## Architecture

```text
webscan/
├── cli.py          CLI, safety notice, argument parsing
├── engine.py       Async orchestration and concurrency
├── crawler.py      Breadth-first URL and form discovery
├── net.py          Proxy, rate limiting, User-Agent, stealth
├── models.py       Finding, severity, confidence, report dataclasses
├── reporter.py     Six output formats and terminal summary
├── risk.py         0-100 score and A-F grade
├── compliance.py   OWASP Top 10 2021 mapping
├── diff.py         New/fixed/changed report comparison
└── plugins/        Built-in and entry-point-discovered checks
```

Runtime dependencies are deliberately small: `aiohttp` and `PyYAML`.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check webscan tests
mypy webscan
pytest -q
```

To write a plugin, subclass `BasePlugin`, implement `run()`, and register it
under the `webscan.plugins` entry-point group. Reuse the active helpers for
retry, soft-404 calibration, and response similarity checks.

## Legal

WebScan is for **authorized security testing only**. Use it solely on systems
you own or have explicit written permission to test. Unauthorized scanning may
be illegal in your jurisdiction. You are solely responsible for your use.

<div align="center">

Made for responsible testing and fewer false positives.

[Star the project](https://github.com/lutzashl290788-cell/webscan/stargazers) ·
[Report a bug](https://github.com/lutzashl290788-cell/webscan/issues) ·
[Contribute](CONTRIBUTING.md)

</div>
