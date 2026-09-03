<div align="center">

<img src="assets/header.svg" alt="WebScan — automated web security auditor" width="820" />

# WebScan

**Discover. Verify. Report.**

An asynchronous web security auditor that verifies findings against response
content before it reports them — so the list you hand a developer is short,
specific, and worth their time.

[![CI](https://img.shields.io/github/actions/workflow/status/lutzashl290788-cell/webscan/ci.yml?style=flat-square&label=CI&logo=githubactions&logoColor=white)](https://github.com/lutzashl290788-cell/webscan/actions)
[![PyPI](https://img.shields.io/pypi/v/webscan-security?style=flat-square&logo=pypi&logoColor=white&label=PyPI)](https://pypi.org/project/webscan-security/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/github/license/lutzashl290788-cell/webscan?style=flat-square&color=00d26a)](LICENSE)
[![Plugins](https://img.shields.io/badge/plugins-41-2f81f7?style=flat-square)](#plugin-catalog)
[![Formats](https://img.shields.io/badge/report%20formats-6-8250df?style=flat-square)](#reports)

<img src="assets/demo.svg" alt="WebScan terminal scan summary" width="760" />

</div>

> [!WARNING]
> **Scan only what you are authorized to scan.** Use WebScan solely on systems you
> own or have explicit written permission to test. You are responsible for
> authorization, scope, rate limits, and the impact of every request it sends.

---

## Contents

<table>
<tr>
<td valign="top" width="50%">

**Getting started**

- [Why WebScan](#why-webscan)
- [Install](#install)
- [Quick start](#quick-start)
- [Presets](#presets)
- [Choose your workflow](#choose-your-workflow)

</td>
<td valign="top" width="50%">

**How it works**

- [The scan pipeline](#the-scan-pipeline)
- [Plugin catalog](#plugin-catalog)
- [Confidence and severity](#confidence-and-severity)
- [Reports](#reports)
- [Risk, compliance, and diffing](#risk-compliance-and-diffing)

</td>
</tr>
<tr>
<td valign="top" width="50%">

**Reference**

- [Local dashboard](#local-dashboard)
- [CLI reference](#cli-reference)
- [Configuration profiles](#configuration-profiles)
- [CI/CD](#cicd)
- [Python API](#python-api)

</td>
<td valign="top" width="50%">

**Project**

- [Architecture](#architecture)
- [Benchmark](#benchmark)
- [Documentation](#documentation)
- [Development](#development)
- [Security](#security) · [Legal](#legal)

</td>
</tr>
</table>

---

## Why WebScan

Most scanners fail in one of two directions: they report everything and bury the
real issue, or they stay quiet and miss it. WebScan is built around the first
problem — every heuristic finding is checked against what the server actually
returned before it reaches the report.

| Principle | What it means in practice |
|---|---|
| **Signal over noise** | Findings carry a `firm` / `tentative` / `informational` confidence tag. Soft-404 calibration, response-similarity checks, and site-wide deduplication run before anything is reported. |
| **Safe by default** | The default profile skips checks that mutate state or call external services. `--safe-mode` lowers concurrency, caps the request rate, respects `robots.txt`, and sends an honest User-Agent. |
| **Built for review** | Terminal output a human can read, `--explain` in plain language, evidence attached to findings, and `--suggest-fixes` for copy-paste remediation. |
| **Automation ready** | Six report formats, risk gates, report diffing, SARIF for Code Scanning, and webhooks — all with meaningful exit codes. |
| **Small surface** | Two runtime dependencies: `aiohttp` and `PyYAML`. Everything heavier is an opt-in extra. |

---

## Install

```bash
python -m pip install webscan-security
```

The PyPI badge above shows the version `pip install` will actually give you.
GitHub releases can run ahead of PyPI; to track the newest code, install from
the repository instead:

```bash
python -m pip install "git+https://github.com/lutzashl290788-cell/webscan"
```

<details>
<summary><b>Optional extras</b></summary>

<br>

```bash
python -m pip install 'webscan-security[ai]'     # Claude triage and summaries
python -m pip install 'webscan-security[serve]'  # local HTTP backend + dashboard
python -m pip install 'webscan-security[dev]'    # test and lint tooling
```

| Extra | Pulls in | Needed for |
|---|---|---|
| `ai` | `anthropic` | `--ai-triage`, `--ai-summary` (also needs `ANTHROPIC_API_KEY`) |
| `serve` | `fastapi`, `uvicorn` | `webscan serve` and the local history dashboard |
| `dev` | `pytest`, `ruff`, `mypy`, … | Running the test suite and the linters |

</details>

<details>
<summary><b>From source, Docker, and pipx</b></summary>

<br>

```bash
# From a clone
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan
python -m pip install .

# Isolated CLI install
pipx install webscan-security

# Docker — nothing to install
docker run --rm ghcr.io/lutzashl290788-cell/webscan -t https://example.com
```

Full details, including offline installs, are in
[docs/installation.md](docs/installation.md).

</details>

**Requirements:** Python 3.11 or newer. Linux, macOS, and Windows.

---

## Quick start

**1. Run a polite first audit.** `--safe-mode` keeps the request rate low;
`--explain` adds a plain-language paragraph under each finding.

```bash
webscan -t https://example.com --safe-mode --explain
```

**2. Save something you can share.**

```bash
webscan -t https://example.com --safe-mode --format json html md -o reports/example
```

This writes `reports/example.json`, `.html`, and `.md`. The HTML report is
self-contained — it opens in a browser on a machine that has never heard of
WebScan.

**3. Keep only what is worth acting on.**

```bash
webscan -t https://example.com --min-severity high --min-confidence firm
```

---

## Presets

A preset bundles the plugin selection, crawl behaviour, and confidence threshold
into one flag, so a useful scan does not require writing a config file first.

| Preset | What it does | Reach for it when |
|---|---|---|
| `quick` | Default plugins, `firm` findings only | You want a fast, high-confidence look |
| `safe` | Polite crawl, soft-404 handling, `firm` findings only | The target is production and you are a guest on it |
| `full` | Safe crawl plus DNS, technology, and robots/sitemap recon | You are profiling a target, not just checking it |
| `active` | Defaults plus the heavier active checks | You have authorisation for intrusive probes |

```bash
webscan -t https://example.com --preset quick
webscan -t https://example.com --preset safe
webscan -t https://example.com --preset full
webscan -t https://example.com --preset active
```

A preset sets **defaults**, so explicit flags still win: `--preset safe --depth 4`
gives you the safe preset with a deeper crawl. Presets cannot be combined with
`--config` / `--profile` — pick one source of configuration, and WebScan will
say so plainly if you pick both.

---

## Choose your workflow

| You need to… | Start here | You get |
|---|---|---|
| Baseline a site you own | `webscan -t https://example.com --safe-mode` | Terminal summary |
| Find routes before auditing | `webscan -t https://example.com --crawl --depth 3` | Crawl plus a scan of everything discovered |
| See only actionable signal | `--min-severity high --min-confidence firm` | High-impact, directly verified findings |
| Scan behind a login | `--cookie`, `--header`, `--basic-auth`, `--login-url` | Session-aware checks |
| Compare two deployments | `webscan diff baseline.json current.json --fail-on-new` | New, fixed, and changed findings |
| Gate a pull request | `--format sarif -o report --fail-on-risk 70` | SARIF artifact and a non-zero exit code |
| Share results outside the team | `--format html md --anonymize` | Redacted, offline-readable reports |
| Revisit past scans | `webscan serve` | Local dashboard at `http://127.0.0.1:8000` |

---

## The scan pipeline

```text
   targets (-t) or file (-f)
              │
              ▼
   normalize + deduplicate
              │
              ├──── optional crawl (--crawl) ────▶ discovered URLs
              ▼
        async engine
              │
              ├──▶ passive plugins      inspect what the server already sent
              └──▶ active plugins       send probes, then verify the response
              │
              ▼
   content verification → confidence → severity → site-wide dedup
              │
              ├──▶ terminal summary
              ├──▶ json · jsonl · md · html · sarif · csv
              └──▶ risk score · OWASP mapping · diff · webhook
```

Concurrency is bounded twice — by the connection pool and by a semaphore — so a
scan cannot accidentally flood a target. `--stealth` drops both to a single
in-flight request.

---

## Plugin catalog

WebScan ships **41 plugins**: **33 run by default**, **8 are opt-in**. Run
`webscan --list-plugins` for the registry as installed; the annotated catalogue
is in [docs/plugins.md](docs/plugins.md).

### Passive checks

These read what the server already sent — responses, certificates, HTML,
JavaScript, cookies, headers — and never send an exploit payload.

`headers` · `secrets` · `cors` · `cookies` · `ssl_tls` · `security_txt` ·
`jwt_audit` · `csrf` · `clickjacking` · `verbose_errors` ·
`prototype_pollution` · `csp_analyzer` · `waf_detect` · `websocket_security`

### Active checks

These send probes and then verify the response before reporting anything.

| Plugin | Coverage |
|---|---|
| `config_files` | Exposed `.env`, `.git`, backups, keys, dumps, common config files |
| `directories` | Admin panels, debug paths, open listings, sensitive directories |
| `sql_injection` | Error-based, boolean-blind, and time-blind variants |
| `xss` | Reflected parameters, classified by injection context |
| `path_traversal` · `lfi_rfi` | Unix/Windows traversal and PHP wrapper probes, content verified |
| `open_redirect` | Redirect payload variants with `Location` host validation |
| `ssrf` | Cloud metadata and localhost response signatures |
| `http_methods` | Dangerous `PUT`, `DELETE`, `TRACE`, `CONNECT`, `PATCH` |
| `subdomains` | Certificate Transparency, with optional DNS brute force |
| `graphql_depth` | Depth abuse and field-suggestion disclosure |
| `xxe` | XML entity probes with per-scan markers |
| `idor` | Object-ID variation with similarity and auth-error suppression |
| `cache_poisoning` · `host_header_injection` | Host and forwarding header reflection |
| `ssti` | Jinja2, Twig, FreeMarker, ERB, and Smarty syntax |
| `backup_files` | Source-verified `.bak`, `.old`, `.orig`, `~`, `.save` |
| `file_upload` | Harmless upload with predicted-URL accessibility check |
| `web_cache_deception` | Dynamic URLs with static extensions on sensitive responses |

### Opt-in checks

Eight plugins stay out of the default run, for three distinct reasons.

| Plugin | Coverage | Why it is opt-in |
|---|---|---|
| `mass_assignment` | API role and property injection | 🔧 May mutate target state |
| `race_condition` | Concurrent request comparison | 🔧 May mutate target state |
| `request_smuggling` | CL.TE and TE.CL timing probes | 🔧 May mutate target state |
| `cve_lookup` | Detected software mapped to known CVEs | 🌐 Queries an external database |
| `dns_security` | DNSSEC, CAA, SPF, DMARC, DKIM | 🌐 Queries public DNS resolvers |
| `graphql` | Endpoints with introspection enabled | 🔍 Reconnaissance, not a vulnerability |
| `tech_fingerprint` | Server, framework, CMS identification | 🔍 Reconnaissance, not a vulnerability |
| `robots_sitemap` | `robots.txt` / `sitemap.xml` leaks and hygiene | 🔍 Reconnaissance, not a vulnerability |

```bash
webscan -t https://example.com --plugins graphql cve_lookup   # ONLY these two
webscan -t https://example.com --preset active                # defaults + active opt-ins
webscan -t https://example.com --preset full                  # defaults + recon opt-ins
```

> [!IMPORTANT]
> `--plugins` **replaces** the default set — it does not add to it. When you want
> the defaults plus something extra, use a preset or list every plugin you want.

---

## Confidence and severity

Every finding carries both. Severity says how bad it would be; confidence says
how sure WebScan is that it is real.

| Confidence | Meaning | Typical use |
|---|---|---|
| `firm` | Directly observed, or proven by a content check | Hand straight to a developer |
| `tentative` | Strong heuristic that needs a human to confirm | Triage queue |
| `informational` | Best-practice note or manual-review signal | Hardening backlog |

```bash
webscan -t https://example.com --min-confidence firm   # strongest false-positive filter
```

`--min-confidence` drops findings from **all** output, reports included.
`--min-severity` filters the console summary only.

---

## Reports

| Format | Flag | Best for |
|---|---|---|
| JSON | `--format json` | APIs, archives, custom tooling |
| JSONL | `--format jsonl` | `jq`, streaming, line-oriented pipelines |
| Markdown | `--format md` | Pull requests and human review |
| HTML | `--format html` | Self-contained stakeholder reports |
| SARIF | `--format sarif` | GitHub Code Scanning, IDE integrations |
| CSV | `--format csv` | Excel, Jira, data imports |

```bash
# One finding per line, then filter with jq
webscan -t https://example.com --format jsonl -o findings
jq 'select(.severity == "critical")' findings.jsonl

# Redact local paths, hostname/username, and private IPs before sharing
webscan -t https://example.com --format html sarif -o public-report --anonymize
```

Full details — every field, the anonymiser's guarantees, and the HTML
report's structure — are in [docs/reports.md](docs/reports.md).

---

## Risk, compliance, and diffing

```bash
# 0-100 score with an A-F grade, plus OWASP Top 10 2021 mapping
webscan -t https://example.com --risk-score --compliance

# What changed since the last run?
webscan diff baseline.json current.json --fail-on-new
```

`webscan diff` reads two JSON reports and prints what is **new**, what was
**fixed**, and what **changed**. With `--fail-on-new` it exits `1` as soon as a
new CRITICAL or HIGH finding appears — which is the check you want in CI.

---

## Local dashboard

```bash
python -m pip install 'webscan-security[serve]'
webscan serve
```

Open `http://127.0.0.1:8000` to launch scans, revisit previous ones, and filter
findings by severity, confidence, plugin, or free-text search.

History lives in `~/.webscan/history.db` and is **never uploaded**. Point it
somewhere else with `--history-db /path/to/history.db` or `WEBSCAN_HISTORY_DB`.

> [!CAUTION]
> `serve` binds to `127.0.0.1` on purpose. It is a local helper, not a hardened
> public service — put your own authentication and rate limiting in front of it
> before exposing it to any network you do not control.

---

## CLI reference

<details open>
<summary><b>Targets, discovery, and authentication</b></summary>

```text
Targets
  -t, --target URL [URL ...]     One or more target URLs
  -f, --file FILE                One URL per line (# comments allowed)

Discovery
  --crawl                        Spider each target before scanning
  --depth N                      Maximum crawl depth (default: 2)
  --max-urls N                   URL cap per seed (default: 200)
  --scope DOMAIN                 Restrict the crawl to a host
  --exclude PATTERN ...          Skip URLs containing these substrings
  --ignore-robots                Ignore robots.txt while crawling

Authentication
  --cookie STRING                Raw Cookie header
  --header NAME:VALUE            Extra header (repeatable)
  --basic-auth USER:PASS         HTTP Basic credentials
  --login-url URL                Form login endpoint
  --login-data STRING            URL-encoded login body
```

</details>

<details>
<summary><b>Network, safety, and evasion</b></summary>

```text
  --safe-mode                    Polite rate, honest UA, lower concurrency, robots respected
  --stealth                      UA rotation, jitter, concurrency 1, spoofed forwarding headers
  --proxy URL                    HTTP or SOCKS5 proxy
  --user-agent STRING            Override the User-Agent
  --random-agent                 Rotate browser-like User-Agents
  --delay SEC                    Fixed delay before each target
  --random-delay                 Jitter --delay by x0.5-x1.5
  --rate-limit N                 Cap requests per second
  --retries N                    Retries on timeouts and 429/5xx (default: 2)
  --retry-backoff SEC            Base backoff, doubled each attempt (default: 0.5)
  --strict-ssl                   Enforce certificate verification
  --no-verify-ssl                Skip verification (already the default; kept for compatibility)
  --no-bruteforce                Certificate Transparency only in the subdomains plugin
  --soft-404                     Calibrate against a bogus path and suppress soft-404 matches
```

> TLS verification is **off by default** so the scanner can audit hosts with
> self-signed or expired certificates. Turn it on with `--strict-ssl` when a
> valid certificate is itself part of what you are checking.

</details>

<details>
<summary><b>Plugins, output, and performance</b></summary>

```text
Plugins and configuration
  --preset NAME                  quick | safe | full | active
  --config FILE / --profile NAME YAML config file and a named profile
  --plugins NAME [...]           Select plugins (replaces the default set)
  --list-plugins                 Print the registry and exit

Output
  -o, --output PATH              Report base path, without extension
  --format FMT [...]             json | jsonl | md | html | sarif | csv (default: json md)
  --min-severity LEVEL           critical | high | medium | low | info
  --min-confidence LEVEL         firm | tentative | informational
  --explain                      Plain-language explanation under each finding
  --suggest-fixes                Copy-paste remediation (nginx, Python, curl)
  --anonymize                    Redact local paths, host/user data, private IPs
  --risk-score                   Print the 0-100 score and A-F grade
  --compliance                   Map findings to OWASP Top 10 2021
  --webhook-url URL              Post a summary to Slack/Discord/Teams/HTTP
  --ai-triage / --ai-summary     Claude triage and executive summary ([ai] extra)
  --fail-on LEVEL                Exit 1 at or above this severity (default: critical/high)
  --fail-on-risk N               Exit 1 when the risk score is below N
  -v / -q / --no-color           Verbose, quiet, or no ANSI colour

Performance
  -c, --concurrency N            Max concurrent targets (default: 10)
  --timeout SEC                  Per-request timeout (default: 10)
```

</details>

**Subcommands:** `webscan serve` (local backend) and `webscan diff` (compare two
reports). `webscan --help` always prints the reference for your installed
version; `webscan -V` prints that version.

---

## Configuration profiles

Keep reusable settings in YAML and commit them. Explicit CLI flags override
whatever the profile says.

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

Every supported key is documented in
[docs/configuration.md](docs/configuration.md).

---

## CI/CD

### Exit codes

| Code | When |
|---|---|
| `0` | The scan completed and no gate was tripped |
| `1` | A finding at or above `--fail-on` (default: CRITICAL/HIGH), a risk score below `--fail-on-risk`, a new regression under `diff --fail-on-new`, or a fatal error |

### GitHub Actions

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

### Docker

```bash
docker run --rm ghcr.io/lutzashl290788-cell/webscan -t https://example.com

docker run --rm -v "$(pwd)/reports:/reports" ghcr.io/lutzashl290788-cell/webscan \
  -t https://example.com -o /reports/scan --format json html
```

GitLab CI, Jenkins, and gating strategies are covered in
[docs/ci-cd.md](docs/ci-cd.md).

---

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

The same `ScanReport` renders through `Reporter(report)` with `.to_json()`,
`.to_jsonl()`, `.to_markdown()`, `.to_html()`, `.to_sarif()`, and `.to_csv()`.
See [docs/python-api.md](docs/python-api.md).

---

## Architecture

```text
webscan/
├── cli.py          CLI parsing, presets, safety notice, subcommands
├── engine.py       Async orchestration and concurrency limits
├── crawler.py      Breadth-first URL and form discovery
├── net.py          Proxy, rate limiting, User-Agent, stealth
├── models.py       Finding, Severity, Confidence, ScanReport
├── reporter.py     Six output formats and the terminal summary
├── risk.py         0-100 score and A-F grade
├── compliance.py   OWASP Top 10 2021 mapping
├── diff.py         New / fixed / changed report comparison
├── server.py       Optional HTTP backend ([serve] extra)
└── plugins/        Built-in and entry-point-discovered checks
```

Runtime dependencies are deliberately small — `aiohttp` and `PyYAML`. The module
map and design constraints are in [docs/architecture.md](docs/architecture.md).

---

## Benchmark

A cold, single-target Safe Mode run against other general-purpose scanners.
Treat it as a reference point, not a promise for every network or target.

| Scanner | Time | Findings | False positives | Coverage |
|---|---:|---:|---:|---:|
| **WebScan 2.8** | **7.1s** | **16** | **0** | **41 plugins** |
| Nuclei 3.8 | 34.2s | 21 | not measured | template-based |
| Nikto 2.6 | 42.6s | 30 | 5+ observed | legacy checks |

Target `httpbin.org`, 41 plugins, Safe Mode, one cold run. Reproduce it with
`python benchmarks/run_benchmark.py --help`.

---

## Documentation

Full reference documentation lives in [`docs/`](docs/README.md).

| Guide | Covers |
|---|---|
| [Installation](docs/installation.md) | pip, extras, Docker, pipx, offline installs |
| [Quickstart](docs/quickstart.md) | First scan to first report |
| [Plugin reference](docs/plugins.md) | All 41 checks, opt-in rationale, the confidence model |
| [Configuration](docs/configuration.md) | YAML profiles, every key, environment variables |
| [Reports](docs/reports.md) | Six formats, anonymising, diffing, risk scoring, dashboard |
| [CI/CD integration](docs/ci-cd.md) | Exit codes, gating, GitHub Actions, GitLab, Jenkins |
| [Python API](docs/python-api.md) | `scan()`, report dataclasses, rendering |
| [Plugin development](docs/plugin-development.md) | The `BasePlugin` contract, helpers, testing, publishing |
| [Architecture](docs/architecture.md) | Module map, pipeline, concurrency, design constraints |
| [Troubleshooting](docs/troubleshooting.md) | Install problems, noisy results, missing checks, CI issues |

---

## Development

```bash
python -m pip install -e ".[dev]"

ruff check webscan tests
mypy webscan
pytest -q
```

Install the git hooks to run the same checks CI does:

```bash
pip install pre-commit && pre-commit install
```

To add a check: subclass `BasePlugin`, implement `run()`, and register it under
the `webscan.plugins` entry-point group. Reuse the active helpers for retry,
soft-404 calibration, and response similarity so your plugin inherits the same
false-positive discipline as the built-ins. The contract is in
[docs/plugin-development.md](docs/plugin-development.md); the contribution
process is in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

Found a vulnerability **in WebScan itself**? Please do not open a public issue —
report it privately through
[GitHub Security Advisories](https://github.com/lutzashl290788-cell/webscan/security/advisories/new).
Response targets, supported versions, and the security model of running a scan
are in [SECURITY.md](SECURITY.md).

## Legal

WebScan is for **authorized security testing only**. Use it solely on systems you
own or have explicit written permission to test. Unauthorized scanning may be
illegal in your jurisdiction. You are solely responsible for how you use it.

<div align="center">
<br>

**Made for responsible testing and fewer false positives.**

[Documentation](docs/README.md) ·
[Report a bug](https://github.com/lutzashl290788-cell/webscan/issues/new/choose) ·
[Security policy](SECURITY.md) ·
[Contribute](CONTRIBUTING.md) ·
[Changelog](CHANGELOG.md)

</div>
