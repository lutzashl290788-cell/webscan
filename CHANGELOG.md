# Changelog

All notable changes to WebScan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **`config_files`: no more false-positive CRITICALs on executed scripts** (#32).
  A request for `/wp-config.php`, `/config.php`, `/settings.py` etc. that the
  server *executes* returns `200` with an empty (or rendered-HTML) body and
  discloses nothing. The plugin previously flagged any `200` as exposed.
  Detection is now content-aware: empty bodies are never flagged, executable
  scripts are reported only when their raw source actually leaks (source markers
  like `<?php`, `define(`, `import ` present), and a genuine source leak is still
  caught as CRITICAL.

### Performance
- **Plugins now run concurrently per target** instead of one after another.
  Single- and few-target scans are dramatically faster; request pressure stays
  bounded by the shared connector's per-host connection limit, so scans are no
  less polite.
- **Crawler fetches each depth level in parallel** (bounded by a new
  `CrawlConfig.concurrency`, wired to `--concurrency`) instead of one URL at a
  time, greatly speeding up `--crawl` on larger sites.

## [2.0.0] - 2026-06-15

The **2.0** milestone: WebScan grows from a configuration checker into a complete
async web-security auditor — **19 plugins**, a crawler, authentication, polite
**Safe Mode**, proxy/SOCKS5 evasion, five report formats (incl. SARIF & CSV),
live **CVE lookup against the NVD's 350,000+ records**, and a library API. Backed
by **214 tests at 94% coverage** and a reproducible benchmark where it finishes a
full scan in **7.3s — 4.7× faster than Nuclei, 5.8× faster than Nikto, with zero
false positives**.

### Highlights since 1.0
- **19 plugins total** (up from 7): added `xss`, `path_traversal`, `open_redirect`,
  `tech_fingerprint`, `ssl_tls`, `ssrf`, `subdomains`, `robots_sitemap`, `secrets`,
  `graphql` and `cve_lookup`, plus blind (boolean/time) SQL injection.
- **Crawler/spider** with depth, scope, exclusion and `robots.txt` support.
- **Authentication**: cookie, header, basic-auth and form-login.
- **Safe Mode** (`--safe-mode`) — polite preset for site owners.
- **Proxy / SOCKS5, User-Agent rotation and request pacing** for stealth.
- **SARIF 2.1.0**, **HTML**, **CSV** and **JSON Lines** report formats.
- **CVE integration** — maps detected software/versions to NVD CVEs (~350K records).
- **Library mode** — `webscan.scan()` / `scan_sync()` for embedding.
- **Quality bar**: 214 tests, 94% coverage, `mypy --strict` clean, ruff clean,
  enforced by an `--cov-fail-under=80` CI gate.
- **Benchmark**: 7.3s end-to-end, 28 findings, 0 false positives — see the
  [README benchmark](README.md#-benchmark).

### Added
- **Test suite expanded to 214 tests at 94% line coverage**, including full
  coverage of the CLI, TLS probing, auth/form-login, subdomain resolution and the
  shared HTTP helpers.
- **Benchmark, feature comparison and code-quality sections** in the README,
  documenting WebScan's speed and accuracy against Nuclei, Nikto, OWASP ZAP and
  Burp Suite Pro.
- **Library mode**: WebScan can now be used as a Python package —
  `webscan.scan(targets, ...)` (async) and `webscan.scan_sync(...)` (blocking)
  return the same `ScanReport` the CLI produces, for embedding in recon
  pipelines/notebooks. The plugin registry moved to `webscan/registry.py` as the
  single source of truth shared by the CLI and the API; `__init__.py` now
  exports `scan`, `scan_sync`, `ScanReport`, `Finding`, `Severity`, `Reporter`
  and the registry. CLI behaviour is unchanged. (#31)
- **JSON Lines output** (`--format jsonl`): emits one self-contained JSON
  object per finding (NDJSON), with target/scan context inlined on each line,
  for `jq`/`grep` pipelines and streaming into other tools. (#30)
- **Soft-404 detection** (`--soft-404`): calibrates against a non-existent path
  before probing and suppresses `directories`/`config_files` findings that merely
  echo the server's "not found" template. Cuts the false-positive flood on sites
  that answer `200`/`403` for every request. Opt-in, offline (stdlib similarity),
  default behaviour unchanged. (#29)
- **`cve_lookup` plugin** (opt-in): maps software/version banners (Server,
  X-Powered-By) to known CVEs via the NVD API, reporting the CVE id, year,
  description and CVSS severity, each linked to its official record on
  [cve.org](https://www.cve.org). (#28)
- **`graphql` plugin** (opt-in): detects GraphQL endpoints with introspection
  enabled (full-schema disclosure) across common paths. (#11)
- **JWT and generic `api_key=`/secret detection** in the `secrets` plugin. (#10)
- **Retry with exponential backoff** (`--retries`, `--retry-backoff`) for
  network-heavy lookups, riding out transient timeouts and `429`/`5xx`. (#16)
- **Entry-point plugin discovery**: built-ins are registered under the
  `webscan.plugins` entry-point group and discovered via `importlib.metadata`,
  so third-party packages can add plugins. (#17)
- **YAML config profiles** (`--config`, `--profile`): reusable scan settings;
  CLI flags override file values, which override built-in defaults. (#19)
- **Published Docker image**: CI builds and pushes to GHCR on `main`/tags. (#20)
- **Coverage gate in CI** (`--cov-fail-under=80`) plus tests for the engine, CLI,
  config/retry layers and previously-untested plugins. (#23)
- **`--explain`**: prints a plain-language, jargon-free explanation under each
  finding so non-experts understand what it means and why it matters (offline,
  no LLM dependency).
- **`robots_sitemap` plugin**: analyses robots.txt / sitemap.xml for hygiene and
  flags sensitive paths accidentally advertised via `Disallow:`.
- **`secrets` plugin**: detects leaked API keys / credentials in HTML and served
  JavaScript (AWS, Anthropic, OpenAI, Google, Stripe, GitHub, Slack, HuggingFace,
  private-key blocks). Matched secrets are redacted in the report.
- **Safe Mode** (`--safe-mode`): polite preset — caps the request rate (~2 req/s),
  uses an honest User-Agent, lowers concurrency and respects `robots.txt`.
- **Report anonymisation** (`--anonymize`): strips local paths, hostname/username
  and private IPs (RFC 1918 / loopback / link-local) from exports.
- **`--rate-limit`**, **`--random-delay`** and **`--no-verify-ssl`** network flags.
- **`--fail-on LEVEL`**: configurable CI exit-code threshold.
- **CSV report format** (`--format csv`).
- **`ssl_tls` plugin**: weak TLS protocols, expired/expiring certificates, missing HSTS.
- **DNS brute force** for the `subdomains` plugin (alongside crt.sh); `--no-bruteforce`.
- Animated SVG README header and terminal demo.
- Authorised-use legal disclaimer printed on every interactive run.

### Changed
- GitHub Actions bumped to `@v6` (native Node 24).

## [1.3.0] - 2026-06-10

### Added
- **SARIF 2.1.0 report format** (`--format sarif`) for GitHub Code Scanning.
- **GitHub Actions workflows**: CI (ruff + mypy + pytest, Python 3.10–3.12) and a
  reusable security-scan workflow that uploads SARIF.
- **`ssrf` plugin**: reflected SSRF via internal / cloud-metadata endpoints.
- **`subdomains` plugin**: enumeration via Certificate Transparency (crt.sh).

## [1.2.0] - 2026-06-10

### Added
- Proxy, User-Agent rotation and request pacing (`--proxy`, `--user-agent`,
  `--random-agent`, `--delay`).
- **`path_traversal`**, **`open_redirect`** and **`tech_fingerprint`** plugins.
- Self-contained **HTML report** (`--format html`).
- Coloured console output and `--min-severity` filtering.
- Multi-stage **Dockerfile** and `.dockerignore`.

## [1.1.0] - 2026-06-10

### Added
- **Crawler / spider** with depth, scope, exclusion and `robots.txt` support.
- **Form parsing** via a dependency-free HTML parser.
- **`xss` plugin**: reflected XSS with injection-context classification.
- **Blind SQL injection**: boolean-based and time-based, added to `sql_injection`.
- **Authentication**: cookie, header, basic-auth and form-login support.

## [1.0.0]

### Added
- Initial release: async scan engine, plugin architecture, JSON + Markdown reports.
- Plugins: `config_files`, `headers`, `directories`, `sql_injection` (error-based),
  `cors`, `cookies`, `http_methods`.

[Unreleased]: https://github.com/lutzashl290788-cell/webscan/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.3...v2.0.0
[1.3.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.2...v1.3
[1.2.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.1...v1.2
[1.1.0]: https://github.com/lutzashl290788-cell/webscan/releases/tag/v1.1
