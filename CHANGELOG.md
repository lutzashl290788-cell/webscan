# Changelog

All notable changes to WebScan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — 3 new plugins (24 → 27 total)

- **`clickjacking` plugin** (passive): audits response headers for
  clickjacking protection. Flags pages with neither `X-Frame-Options` nor
  `Content-Security-Policy: frame-ancestors` as MEDIUM; pages with only the
  legacy X-Frame-Options (CSP missing) as LOW (migration nudge); pages using
  the obsolete `ALLOW-FROM` directive as INFO. Skips non-HTML responses,
  error pages, and short bodies to keep the FP rate low.

- **`cache_poisoning` plugin** (active, content-verified): probes for
  cache-poisoning via Host / X-Forwarded-Host / X-Original-URL /
  X-Rewrite-URL / X-Forwarded-Server header injection. CRITICAL when the
  injected sentinel is reflected in a dangerous location (`<link href>`,
  `<script src>`, `<a href>`, `<form action>`, `<iframe src>`, meta
  refresh, CSS `url()`); MEDIUM for plain-text reflection. Per-scan
  random sentinel so a fixed string in the response can't produce a FP.

- **`host_header_injection` plugin** (active, content-verified): probes
  password-reset endpoints (`/reset`, `/forgot`, `/password-reset`,
  `/account/recover`, `/wp-login.php?action=lostpassword`, etc.) for
  host-header injection. CRITICAL when the injected host appears in a URL
  context (proving the reset link would be poisoned); HIGH (TENTATIVE) for
  plain reflection; INFO for blind poisoning (server accepted the header
  but didn't reflect it — manual email verification needed).

### Changed — open_redirect improvements

- **`open_redirect`: 3 payloads → 13 payloads.** Added protocol-relative
  (`//evil`), backslash (`/\\evil`), triple-slash (`///evil`), URL-encoded
  (`https://evil%2f`), CRLF (`https://evil/\n`), and at-sign variants that
  bypass naïve host validation.
- **`open_redirect`: 16 → 30+ recognised parameter names.** Added `from`,
  `ref`, `referer`, `referrer`, `back`, `redir`, `go`, `out`, `exit`,
  `link`, `site`, `to`, `view`, `location`, `page`, `nav`, `navigate`.
- **`open_redirect`: now uses `Confidence.FIRM`** (content-verified via
  parsed `Location` host, not substring).
- **`open_redirect`: cap of 5 params per target** to bound request pressure.

### Changed — full README refresh

- Updated plugin count from 24 to **27** everywhere (header tagline, Code
  Quality table, Comparison table).
- Updated test count from 214 to **478** and source-file count from 39 to
  **48** in the Code Quality section.
- Added a **Confidence dimension** subsection explaining `firm` / `tentative`
  / `informational` and the `--min-confidence` flag.
- Added rows for all 3 new plugins and the improved `open_redirect` to the
  plugins table, with FP-reduction notes (content verification, soft-404,
  similarity threshold, etc.).
- Added new features to the "Bug hunters" and "Site owners" audience
  tables (retry with backoff, 5-header cache-poisoning probes, passive-first
  design, `--explain` mode, confidence dimension).
- Refreshed the **Comparison** table: added "Confidence dimension",
  "Soft-404 filter", and "Retry with backoff" rows where WebScan leads.
- Refreshed the **Architecture** diagram to list all 27 plugins and the new
  `_active_helpers.py` shared module.

### Changed — false-positive reduction across all 4 new plugins

- **`lfi_rfi`: replaced size-delta heuristic with structural similarity
  ratio.** The old logic fired a TENTATIVE finding whenever the probe
  response differed from the baseline by ≥50 bytes — but ad rotation,
  CSRF-token rotation, and per-request timestamps easily produce 50-byte
  deltas on legitimate pages. The new logic uses `SequenceMatcher.ratio()`
  (the same approach as the IDOR plugin) and only flags when the response
  is structurally *different* (similarity < 0.65), with a length-ratio
  sanity check (0.2–5.0×) to suppress wildly different responses.
- **`lfi_rfi`: added soft-404 calibration.** Servers that answer every
  path with the same templated 200 page no longer produce a flood of
  TENTATIVE findings — the plugin calibrates against a bogus path up
  front and suppresses probes that match the soft-404 template.
- **`lfi_rfi`: added "file not found" marker suppression.** A probe
  response containing `file not found`, `failed to open stream`,
  `Warning: include(…):`, etc. is now treated as an explicit error (the
  server did process the path but the file doesn't exist) and is not
  flagged TENTATIVE — interesting but not exploitable.
- **`xxe`: INFO finding now requires XML/JSON response shape.** Previously,
  any 200 response to a POST XML probe triggered an INFO finding. Now the
  response must look like XML or JSON (per Content-Type or body prefix),
  not an HTML error page. This cuts the most common FP category (web
  frameworks returning HTML 404 pages for unhandled POST routes).
- **`idor`: raised similarity threshold from 0.75 to 0.85.** The previous
  bar was too permissive — paginated API responses with the same HTML
  skeleton but one row swapped produced false positives. 0.85 is closer
  to "same object returned" while still catching IDOR.
- **`idor`: added object-id equality check.** If the probe response's
  `id`/`user_id`/`_id` JSON field equals the baseline's, the server is
  returning the same object regardless of the URL ID (e.g. it uses the
  session user) — not IDOR. The check uses a regex
  (`"(?:_?id|user_id|…)"`) to be robust against pretty-printed and
  partial JSON.
- **`idor`: added soft-404 calibration.** Same pattern as `lfi_rfi` —
  suppresses IDOR findings when the shifted-ID probe matches the
  calibrated soft-404 template.
- **`csrf`: added SameSite cookie check.** A page that sets a session
  cookie with `SameSite=Strict` or `SameSite=Lax` is already CSRF-protected
  at the browser level — flagging its forms would be a false positive.
  `SameSite=None` does *not* suppress findings (it explicitly opts out).

### Changed — online resilience for all active plugins

- **`lfi_rfi`, `xxe`, `idor`: probes now use retry-with-backoff.** Transient
  `5xx` / `429` responses and network errors no longer abort the whole
  plugin — they ride out with exponential backoff via the existing
  `webscan.retry.request_with_retry` helper. Two retries, 0.3s base delay,
  capped at 4s — enough to ride out a flaky 502/503 without making scans
  slow.
- **New shared helper module: `webscan/plugins/_active_helpers.py`.**
  Centralises `fetch_with_retry`, `fetch_with_headers`, `calibrate_target`,
  `is_soft404`, `body_similarity`, and `looks_like_xml_or_json` so all four
  active plugins use the same retry/soft-404/similarity logic. Reduces code
  duplication and makes future FP-reduction changes easier to apply across
  the board.

### Added
- **Four new security plugins** (20 → 24 total), all with content-verified
  detection to keep the false-positive rate low. Every new plugin uses the
  `Confidence` dimension introduced in `8c6d765` so operators can filter
  heuristic findings with `--min-confidence firm`.

- **`csrf` plugin** (passive): audits HTML forms for missing CSRF protection.
  Flags only **state-changing** forms (POST/PUT/PATCH/DELETE) that lack a
  CSRF token in their fields, AND where the page declares no global
  `<meta name="csrf-token">` tag. To cut false positives, the plugin skips
  login forms (detected via `password` + `username`/`email` field heuristic),
  search forms (POST `/search`, `/filter`, `/sort` actions, or fields named
  `q`/`query`/`search`), cross-origin forms, and forms with no fields. A
  global CSRF meta tag in `<head>` suppresses all findings on the page (the
  token is intended to be picked up by client-side JS).

- **`lfi_rfi` plugin** (active, content-verified): probes file-like URL
  parameters (`file`, `page`, `include`, `path`, `template`, `cat`, …) for
  Local/Remote File Inclusion. Linux path-traversal chains (`../../../etc/passwd`,
  URL-encoded, double-encoded, null-byte), Windows chains (`..\..\windows\win.ini`),
  and PHP wrappers (`php://filter/convert.base64-encode/resource=index.php`).
  **Findings are content-verified**: a CRITICAL is only emitted when the
  response contains actual `/etc/passwd` markers (`root:x:0:0:`), `win.ini`
  markers (`[fonts]`), or the PHP-wrapper response decodes to valid PHP
  source. A heuristic TENTATIVE finding covers the case where the response
  size differs from the baseline by ≥50 bytes without matching any marker.

- **`xxe` plugin** (active, content-verified): probes XML-accepting endpoints
  (detected via `Content-Type: application/xml`, body starting with `<?xml`,
  or URL params named `xml`/`data`/`payload`/`soap`) for XML External Entity
  injection. Sends a per-scan randomised internal-entity probe first; if the
  parser inlines the marker value, escalates to an external-entity probe
  referencing `file:///etc/passwd` (Linux) or `file:///c:/windows/win.ini`
  (Windows). CRITICAL only when actual file markers appear in the response;
  HIGH when internal entities resolve but external didn't leak in-band (could
  still be blind XXE); INFO when the endpoint accepts XML POST without echoing
  the entity (manual review needed). The probe marker is generated fresh per
  scan with `secrets.token_hex(8)` so a fixed string in the response can't
  produce a false positive.

- **`idor` plugin** (active, TENTATIVE): probes API endpoints
  (`/api/`, `/v1/`, `/admin/`, `/graphql`, …) with numeric object IDs shifted
  by ±1. A finding is emitted only when ALL of the following hold: baseline
  returns 200, probe returns 200, probe response has no auth-error markers
  (`unauthorized`, `forbidden`, `access denied`, JSON `{"status": 401}`, …),
  length ratio is within 0.5–2.0× the baseline, Content-Type matches, and
  sequence similarity ≥ 0.75. All findings are TENTATIVE because IDOR is
  semantic — a public API legitimately exposing object N+1 is not IDOR.
  Public-content URLs (no `/api/` in path) are skipped entirely to avoid
  the obvious false-positive category.

### False-positive reduction (cross-cutting)
- The new plugins consistently use `Confidence.FIRM` only when a content
  marker is directly observed, `Confidence.TENTATIVE` for heuristic signals,
  and `Confidence.INFORMATIONAL` for "manual review needed" cases. This
  matches the pattern established by `jwt_audit` and lets operators
  filter with `--min-confidence firm` to keep only directly-verified findings.

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
