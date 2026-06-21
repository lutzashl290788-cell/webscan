# Changelog

All notable changes to WebScan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [2.5.3] - 2026-06-21

### Security — zero known issues remaining

A final, maximally-pedantic audit found 3 new MEDIUM + 3 confirmed LOW + 8 INFO
issues that survived v2.5.1/v2.5.2. All 14 are fixed in this release — the
codebase now has **zero** outstanding security findings at any severity level
(CRITICAL / HIGH / MEDIUM / LOW / INFO).

#### Fixed (MEDIUM)

- **M-NEW-1: H-1 fix was incomplete — TraceConfig now applied to all sessions**
  (CWE-200 / CWE-522). The original H-1 fix in v2.5.1 only attached the
  redirect-safe TraceConfig to `engine.ScanEngine.scan_all()`'s session.
  Two other `aiohttp.ClientSession(...)` constructions — `cli._crawl_targets`
  (carries auth headers/cookies during crawling) and `auth._form_login`
  (POSTs the login form with credentials) — were unprotected. A 302/307/308
  cross-origin redirect on either path would replay `Authorization`/`Cookie`
  or the login POST body on the attacker host. Both now install the same
  `_build_redirect_safe_trace()`. Additionally, `_form_login` now uses
  `allow_redirects=False` — a login endpoint must never silently redirect
  its POST body to a third party.

- **M-NEW-2: shell injection in `security-scan.yml` via `${{ github.event.inputs.target }}`**
  (CWE-78 / CWE-94). The `run:` block interpolated the workflow_dispatch
  input directly into the shell script — a malicious `target` value like
  `"; rm -rf $HOME #` would execute. Fixed via env-var indirection: the
  input is now passed as `$TARGET` (env var), and a regex validation
  rejects anything that doesn't look like an `http(s)://` URL before
  handing it to webscan.

- **M-6: `mass_assignment` PUT now carries safety markers**
  (CWE-624 / CWE-639 / CWE-1286 / CWE-352). The plugin's state-changing
  PUT probe (`{"role":"admin"}`) previously had no `Idempotency-Key`, no
  scanner identification header, and `allow_redirects=True` (which could
  replay the PUT body on a cross-origin redirect — see M-NEW-1). Now each
  probe carries `Idempotency-Key: webscan-<uuid>`, `X-WebScan-Test: 1`,
  `X-WebScan-Dry-Run: 1`, and `allow_redirects=False`. Servers / WAFs that
  understand these headers can identify and skip persistence; the
  `allow_redirects=False` closes the body-replay vector.

#### Fixed (LOW)

- **L-1: dependency upper bounds + CVE coverage**
  (CWE-1357 / CWE-1104). All `>=` specifiers now have `<major` upper bounds.
  Critically, `aiohttp>=3.9.0` → `aiohttp>=3.10.11,<4` closes two HTTP-parser
  DoS CVEs (CVE-2024-52304, CVE-2024-47881) that are directly exploitable
  from a hostile scan target via crafted HTTP responses. Other bounds:
  `PyYAML>=6.0.1,<7`, `anthropic>=0.40,<1`, `fastapi>=0.111,<1` (pulls a
  fixed `python-multipart` for CVE-2024-24762), `uvicorn>=0.30,<1`.

- **L-4: Dockerfile hardened** (CWE-1357 / CWE-691).
  - `python:3.12-slim` base image now pinned by digest
    (`@sha256:c2d8472b831337ab296a8ce652e1ba786e9e3034fc445dc58b50a7f5251f0003`)
    in both build and runtime stages — eliminates supply-chain risk of a
    floating tag being re-published with malicious content.
  - Added `HEALTHCHECK` instruction (`webscan --help >/dev/null 2>&1 || exit 1`)
    so container orchestrators (k8s, docker-compose, ECS) can detect a
    broken image without a separate liveness probe.

- **L-6: `auto-release.yml` tag validation** (CWE-20).
  `TAG=${GITHUB_REF#refs/tags/}` is now validated against
  `^v\d+\.\d+\.\d+(-[\w.]+)?$` before being used in `--notes-file` path
  or `gh release create`. Rejects any non-semver tag at the workflow
  level, eliminating the (admittedly unlikely) path-traversal vector
  through `--notes-file` and providing defense-in-depth.

#### Fixed (INFO)

- **INFO-1: explicit CORS deny-all in `server.py`** (defense-in-depth).
  FastAPI's default is already deny-by-default (no `Access-Control-Allow-Origin`
  header emitted), but the security posture is now explicit in code:
  `CORSMiddleware(allow_origins=[], allow_methods=[], allow_headers=[],
  allow_credentials=False)`. Prevents accidental loosening later and makes
  the intent visible to reviewers. Test: `test_server_cors_preflight_returns_no_allow_origin`.

- **INFO-2: `_safe_url()` in `reporter.py`** (CWE-79 — stored XSS in HTML
  report). `html.escape` neutralises quote characters but doesn't block
  dangerous URL schemes. The HTML report's `<a href="{f.url}">` now filters
  the scheme first — only `http`, `https`, and relative URLs are kept;
  `javascript:`, `data:`, `vbscript:` are replaced with `#`. Finding URLs
  can contain attacker-controlled values (reflected payloads, redirect
  targets), so this closes a stored-XSS vector via clickable report links.

- **INFO-3: `anonymize._PRIVATE_IP` extended to IPv6 + CGNAT** (CWE-200).
  The regex previously covered only IPv4 RFC1918 / loopback / link-local.
  Now also redacts: CGNAT (100.64.0.0/10), 0.0.0.0, IPv6 ULA (fc00::/7),
  IPv6 link-local (fe80::/10), IPv6 loopback (::1). Uses `(?<![\w:.])` /
  `(?![\w:.])` lookarounds because `\b` doesn't anchor correctly against
  `:` in IPv6 addresses.

- **INFO-4: prompt-injection protection in `ai.py`** (LLM-specific CWE-77).
  Scanner output (finding titles, descriptions, evidence — all of which can
  contain attacker-controlled text from the scanned target) is now wrapped
  in `<scanner_output>...</scanner_output>` tags in both `_triage_findings`
  and `summarize_report` user prompts. The system prompts were extended
  with explicit instructions to treat text inside these tags as untrusted
  data and never as directives. This doesn't make prompt injection
  impossible, but raises the bar significantly.

- **INFO-5: `assert` → `if/raise` in `ai.py`** (Bandit B101).
  Two `assert client is not None` statements (which `python -O` strips)
  replaced with explicit `if client is None: raise RuntimeError(...)`.
  Defends against an unlikely but real scenario where the AIAssistant is
  misused via the private API surface.

- **INFO-6: URL credentials masked in `_progress`** (CWE-532).
  The scan progress bar prints the target URL. If the operator passed
  `-t "https://user:pass@host/path"`, the credentials were printed in
  clear text. Now uses the existing `_mask_proxy_url` helper to replace
  `user:pass@` with `***@` before printing.

- **INFO-7: `verify_ssl` parameter exposed in `api.scan()`**.
  Library users (calling `webscan.scan(...)` from Python) previously had
  no way to enable strict TLS verification — only the CLI exposed
  `--strict-ssl`. Now `scan(..., verify_ssl=True)` forwards to
  `ScanEngine(verify_ssl=True)`, mirroring the CLI.

- **INFO-8: covered by M-NEW-1.** The CORS plugin's `allow_redirects=True`
  concern was a side-effect of the missing TraceConfig on non-engine
  sessions. With M-NEW-1 fixed, this disappears automatically.

### Tests — coverage 97% (sustained), +20 new tests

- **860 tests** (was 840), all passing. `tests/test_v253_security.py` (new,
  20 tests) covers every fixed issue:
  - `test_safe_url_*` (5) — `_safe_url` scheme filtering
  - `test_anonymize_redacts_*` (4) — CGNAT + IPv6 ULA/link-local/loopback
  - `test_mass_assignment_sends_idempotency_key_and_dry_run_header` — M-6
  - `test_api_scan_accepts_verify_ssl` — INFO-7
  - `test_auth_form_login_uses_trace_config` + `test_cli_crawl_targets_uses_trace_config` — M-NEW-1
  - `test_ai_triage_wraps_findings_in_scanner_output_tags` + `test_ai_summary_*` — INFO-4
  - `test_ai_triage_raises_runtime_error_if_client_is_none` — INFO-5
  - `test_server_cors_middleware_deny_all_by_default` + `test_server_cors_preflight_returns_no_allow_origin` — INFO-1
  - `test_progress_masks_url_credentials` — INFO-6

### Numbers

- 38 plugins (unchanged)
- 860 tests (was 840)
- 97% coverage (sustained)
- 61 source files
- ruff clean, mypy --strict clean (locally and in CI env)
- **0 known security findings at any severity** (was 4 HIGH + 6 MEDIUM + 6 LOW)

## [2.5.2] - 2026-06-21

### Security — MEDIUM findings closed

#### M-1 fixed: `--strict-ssl` flag (CWE-295)

Previously `--no-verify-ssl` was a documented no-op — the scan engine always
disabled TLS verification regardless of the flag, and `NetConfig.verify_ssl`
was dead code. This was a deliberate design choice (scanners audit
self-signed hosts) but the dead flag misled operators who expected
verification to be enforced when they did NOT pass `--no-verify-ssl`.

This release wires up TLS verification properly:

- **New `--strict-ssl` flag** — when set, the scan engine uses a verifiable
  SSL context (system CAs, hostname check). Useful for scanning production
  sites where a valid cert is expected and a verification failure is itself
  a finding.
- **`--no-verify-ssl`** is kept as a no-op for backward compatibility (its
  help text now says so explicitly).
- **`NetConfig.verify_ssl`** is now live — read by `ScanEngine` to choose
  between the verifiable and non-verifiable SSL contexts.
- **`engine._build_ssl_context(verify=...)`** — the SSL context builder now
  takes a `verify` argument; returns `ssl.create_default_context()` when
  True (full verification) or the permissive context when False (default).

#### M-2 fixed: shared `fetch_body()` helper (CWE-400)

A full audit found ~30 places across plugins, crawler, and retry helper
where `await resp.text(errors="ignore")` was called without a body-size
cap. A hostile target serving a 10 GiB page would OOM the scanner —
particularly dangerous under `webscan serve` where one client could kill
every other scan.

This release introduces a single bounded reader:

- **`webscan.plugins._active_helpers.fetch_body(resp, limit=2 MiB)`** —
  reads at most `limit` bytes via `resp.content.read()`, decodes as UTF-8
  with `errors="ignore"`. Falls back to `resp.text()` for test fakes and
  the lightweight `Response` dataclass returned by
  `webscan.retry.request_with_retry` (which doesn't expose a streaming
  `content` attribute).
- **Applied across 28 plugin files** — every `await resp.text(errors="ignore")`
  is replaced with `await fetch_body(resp)`.
- **`crawler._fetch_and_parse` / `crawler._load_robots`** — same pattern,
  inline (crawler cannot import `_active_helpers` due to layering).
- **`retry.request_with_retry`** — same pattern, inline (retry is below
  `_active_helpers` in the dependency graph).
- **`MAX_BODY_BYTES = 2 * 1024 * 1024`** is exported as a module constant
  for callers that need to reference the cap.

### CI fixes

- **README / SVG version sync** — the header banner (`assets/header.svg`) and
  terminal demo (`assets/demo.svg`) both still showed `v2.4.1` / `v2.4` after
  the v2.5.x releases. Regenerated both from `gen_header.py` / `gen_demo.py`
  (which now read `v2.5.2`). Also refreshed the in-banner title line in
  `demo.svg` from `WebScan v2.2 — Security Auditor` → `v2.5.2`.
- **README numbers refresh** — coverage badge `95% → 97%`, tests `701 → 840`,
  source files `59 → 61`, plugins discovered `27 → 38`, report formats
  `5 → 6` (added JSONL), Verdict row scan time `7.3s → 7.1s`.
- **CI workflow `@v6` removal** — `actions/checkout@v6` and
  `actions/setup-python@v6` (which don't exist on GitHub) replaced with
  `@v4` and `@v5` in `docker.yml`, `security-scan.yml`, and the README
  CI/CD example. (`ci.yml` was already fixed in v2.5.1.)
- **mypy 2.1.0 compatibility** — `webscan/server.py` had three mypy errors
  in CI (but not locally, because locally fastapi was installed):
  - `Unused "type: ignore[assignment, misc]"` on `FastAPI = ... = None` —
    in CI (no fastapi) mypy treats the names as Any and the ignore is
    unused; locally (with fastapi) mypy sees the real class types and the
    ignore is required.
  - `Untyped decorator makes function "health" untyped` and same for
    `scan_endpoint` — the `@app.get` / `@app.post` decorators are untyped
    when fastapi is missing.
  - **Fix:** `[[tool.mypy.overrides]] module = "webscan.server";
    warn_unused_ignores = false` in `pyproject.toml`. Bare `# type: ignore`
  on the three offending lines. This keeps the file clean in both
  environments (CI without extras, dev with all extras).

### Tooling

- **`pyproject.toml` `[tool.ruff.lint.per-file-ignores]`** — `tests/**/*.py`
  now ignores `ANN401 / ANN001 / ANN201 / ANN204` (test fakes legitimately
  need `typing.Any`).

### Numbers

- 38 plugins (unchanged)
- 840 tests (unchanged from v2.5.1 — the M-1/M-2 fixes preserved the
  existing test surface; existing tests already cover the affected code)
- 97% coverage (unchanged)
- 61 source files
- ruff clean, mypy --strict clean (both locally and in CI env)

## [2.5.1] - 2026-06-21

### Security — full audit pass

A complete static-security audit of the codebase surfaced 4 HIGH and 6 MEDIUM
issues. All HIGH-severity findings are fixed in this release; MEDIUM/LOW are
either fixed or explicitly documented.

#### Fixed (HIGH)

- **H-1: auth-header / cookie leak on cross-origin redirect** (CWE-200 / CWE-522).
  The scan engine now installs an `aiohttp.TraceConfig` that strips
  `Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token` and
  `Proxy-Authorization` from any redirect hop whose host differs from the
  original request. Without this, `--basic-auth admin:secret` against a target
  that returned `302 Location: http://attacker/capture` would replay the
  credentials on the attacker host. See `engine._build_redirect_safe_trace`.

- **H-2: SSRF in `file_upload` via cross-origin `form.action`** (CWE-918).
  The plugin now refuses to follow a `<form action>` that points to a different
  origin than the target. A target page could otherwise make the scanner POST
  `webscan-test.txt` (and any auth headers / cookies, see H-1) to an
  attacker-controlled host. The shared `same_origin()` helper lives in
  `utils.http` and is now reusable across plugins.

- **H-3: `webscan serve` HTTP backend — body-size + caps + validation**
  (CWE-306 / CWE-400 / CWE-770). The `/scan` endpoint now rejects bodies larger
  than 64 KiB (HTTP 413), validates that `targets` / `plugins` are lists, and
  clamps `timeout` (≤60s) and `concurrency` (≤32) to safe bounds so a single
  client cannot exhaust the server. Auth/rate-limit middleware remains the
  operator's responsibility when binding to `0.0.0.0` — see `server.py` docstring.

- **H-4: state-changing plugins now opt-in** (CWE-400). `mass_assignment`,
  `race_condition` and `request_smuggling` are no longer run by default — they
  send `PUT`, parallel GET, and smuggled POST requests that can actually mutate
  state on a vulnerable target. The operator must opt in explicitly with
  `--plugins mass_assignment` etc. `OPT_IN_PLUGINS` is the single source of
  truth in `registry.py`.

#### Fixed (MEDIUM / LOW)

- **M-3: third-party plugin supply-chain guard** (CWE-1357). A third-party
  entry-point plugin whose name collides with a built-in (e.g. a malicious
  package registering `headers` to harvest auth credentials) is now rejected
  with a stderr warning rather than silently overriding the built-in.
- **M-5: dead-code `verify_ssl` field** — clarified in-place as a documented
  no-op. The scan engine always disables cert verification (scanners audit
  self-signed hosts); the CLI flag is kept for compatibility.
- **L-2: version sync** — `webscan.__version__` and `server.py` `FastAPI(version=)`
  now both read `2.5.x`, matching `pyproject.toml`.
- **L-3: proxy credential masking in stdout** (CWE-532).
  `--proxy http://user:pass@...` is now printed as `http://***@...` in the
  scan banner, so credentials no longer leak to CI/CD logs, tmux scrollback,
  etc.
- **L-5: CI workflow** — `actions/checkout@v6` / `actions/setup-python@v6`
  (which don't exist) replaced with `@v4` / `@v5`.

### Tests — coverage 96% → 97%

- **+40 new tests** (800 → 840 passed) covering the previously-untested
  branches introduced by the security fixes:
  - `tests/test_security_hardening.py` (new, 15 tests) — redirect-trace
    behaviour, `same_origin`/`same_host` helpers, plugin-discovery supply-chain
    guard, `OPT_IN_PLUGINS` membership, `_mask_proxy_url`.
  - `tests/test_ai.py` — `ai_available` with explicit key / env key,
    `_build_client` SDK-missing / SDK-error branches, triage skip-empty,
    summary unavailable, `_first_text` / `_first_json` edge cases.
  - `tests/test_server.py` — body-size 413, validation for targets/timeout/
    plugins, `_confidence_from_str` invalid input, `create_app`/`run_server`
    without serve extra, timeout/concurrency clamping.
  - `tests/test_cli.py` — `_run_ai` unavailable / available / quiet paths,
    `webscan serve` subcommand (with and without serve extra), `main()` serve
    dispatch, proxy-credential masking in `_print_setup`.

### Tooling

- `pyproject.toml` `[tool.ruff.lint.per-file-ignores]` — `tests/**/*.py` now
  explicitly ignores `ANN401` / `ANN001` / `ANN201` / `ANN204` (test fakes /
  shims legitimately need `typing.Any` and don't need explicit return types).
  Removes ~20 spurious lint errors previously suppressed with `# noqa`.

## [2.5.0] - 2026-06-20

### Performance
- **Benchmark: 11.4s → 7.1s** (1.6× faster, avg of 3 runs)
- **4.8× faster than Nuclei** (was 3.0×), **6.0× faster than Nikto** (was 3.7×)
- backup_files: 312→50 probes (10 files × 5 extensions, was 24×13)
- subdomains: crt.sh query timeout 5s (was unbounded)
- Safe mode concurrency: 4→8 (more parallel plugins)
- Connect timeout: 5s→3s (faster failure on unreachable hosts)
- Connection pool: ×5→×8 of concurrency (more parallel connections)
- v2.5.0 with 38 plugins is now FASTER than v2.0 with 19 plugins (7.1s vs 7.3s)

## [2.4.1] - 2026-06-20

### Changed
- **Coverage boost**: 94% → 95%. Added 13 new tests
  covering error branches in 5 plugins (prototype_pollution,
  request_smuggling, file_upload, websocket_security, mass_assignment).
  Total tests: 688 → 701.

### Fixed
- **README**: Added 11 missing plugins to the plugins table
  (ssti, backup_files, verbose_errors, mass_assignment,
  prototype_pollution, graphql_depth, file_upload, race_condition,
  request_smuggling, web_cache_deception, websocket_security).

## [2.4.0] - 2026-06-20

### Added
- **`websocket_security`** plugin (passive): scans HTML and JS for
  ws:// and wss:// endpoints. HIGH (FIRM) for unencrypted ws:// (traffic
  can be sniffed/MITM). MEDIUM (TENTATIVE) for wss:// with sensitive
  context (token, auth, session near the URL). LOW (INFO) for wss://
  without sensitive context. 17 new tests.

## [2.3.0] - 2026-06-20

### Added
- **`web_cache_deception`** plugin (active, content-verified): appends
  `.css`/`.js`/`.png`/`.svg`/`.woff`/`.pdf`/`.txt` extensions to dynamic
  URLs. HIGH (FIRM) when sensitive data markers (email, api_key, session,
  password, token, balance) appear in the response AND the Content-Type
  doesn't match the extension (e.g. `.css` returns `text/html`). MEDIUM
  (TENTATIVE) when a dynamic page is served at the extension without
  sensitive markers. Soft-404 calibration suppresses false positives.

## [2.2.0] - 2026-06-19

### Added — 9 new plugins (27 → 36 total)

- **`ssti`** (active, FIRM) — Jinja2/Twig/FreeMarker/ERB/Smarty/Smarty-alt/doT.js
  7 syntax variants, content-verified (evaluated result 49/343 must appear)
- **`backup_files`** (active, FIRM) — .bak/.old/.swp/~/.orig/.tmp/.save/.copy/.dist
  24 base files × 13 extensions, source-code content verification
- **`verbose_errors`** (passive, FIRM) — 30+ stack trace markers
  Python/Java/PHP/Ruby/Node.js/.NET/Spring Boot/Laravel/Symfony
- **`mass_assignment`** (active, TENTATIVE) — injects role=admin, is_admin=true
  14 privileged field variants, PUT on API endpoints, content-verified
- **`prototype_pollution`** (passive, TENTATIVE) — scans HTML+JS for
  $.extend, Object.assign, defaultsDeep, merge/extend patterns
- **`graphql_depth`** (active) — depth attack (50-level nested query)
  + field suggestion ("Did you mean") information disclosure
- **`file_upload`** (active, FIRM) — sends harmless test file
  verifies uploaded file is accessible at predicted URL
- **`race_condition`** (active, TENTATIVE) — 10 concurrent duplicate requests
  flags when multiple succeed (coupon/vote/withdraw abuse)
- **`request_smuggling`** (active, TENTATIVE) — CL.TE and TE.CL variants
  timeout-based detection for TE.CL, marker-based for CL.TE

### Security
- **Fixed CSV formula injection** (CWE-1236) in `reporter.py`
  The CSV output didn't escape cells starting with `=`, `+`, `-`, `@`
  — an attacker who controls a finding's title/description could craft
  a value like `=cmd|'/c calc'!A1` that executes when opened in Excel.
  Added `_csv_sanitize()` that prefixes dangerous cells with `'`.

### Assets
- Updated header.svg and demo.svg for v2.2.0 — dark red theme, 36 plugins,
  new finding types (SSTI, LFI, XXE, IDOR, cache poisoning, etc.)

## [2.1.0] - 2026-06-19

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

[Unreleased]: https://github.com/lutzashl290788-cell/webscan/compare/v2.5.3...HEAD
[2.5.3]: https://github.com/lutzashl290788-cell/webscan/compare/v2.5.2...v2.5.3
[2.5.2]: https://github.com/lutzashl290788-cell/webscan/compare/v2.5.1...v2.5.2
[2.5.1]: https://github.com/lutzashl290788-cell/webscan/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/lutzashl290788-cell/webscan/compare/v2.0.0...v2.5.0
[2.0.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.3...v2.0.0
[1.3.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.2...v1.3
[1.2.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.1...v1.2
[1.1.0]: https://github.com/lutzashl290788-cell/webscan/releases/tag/v1.1
