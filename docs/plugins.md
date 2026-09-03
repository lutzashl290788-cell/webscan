# Plugin reference

WebScan ships **41 built-in plugins**. **33 run by default**; **8 are opt-in**
and must be requested explicitly with `--plugins`.

The table below is generated from the plugin registry
(`webscan/registry.py`). Run `webscan --list-plugins` to print the same list
from your installed version, including any third-party plugins.

## Contents

- [Full catalogue](#full-catalogue)
- [Why some plugins are opt-in](#why-some-plugins-are-opt-in)
- [Selecting plugins](#selecting-plugins)
- [Severity and confidence](#severity-and-confidence)
- [Deduplication](#deduplication)

## Full catalogue

| Plugin | Default run | What it checks |
|---|---|---|
| `config_files` | default | Detect publicly accessible config/sensitive files (.env, .git, etc.) |
| `secrets` | default | Detect leaked API keys / secrets in HTML and served JavaScript |
| `headers` | default | Audit HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `directories` | default | Probe sensitive directories and detect open directory listings |
| `sql_injection` | default | Detect error-, boolean- and time-based SQL injection |
| `xss` | default | Detect reflected XSS in URL query parameters |
| `path_traversal` | default | Detect path traversal / local file inclusion in query parameters |
| `open_redirect` | default | Detect open redirects (13 payload variants, content-verified) |
| `ssrf` | default | Detect reflected SSRF via internal/cloud-metadata endpoints |
| `cors` | default | Detect permissive or reflected CORS configurations |
| `cookies` | default | Audit cookie security flags (Secure, HttpOnly, SameSite) |
| `http_methods` | default | Detect dangerous enabled HTTP methods (PUT, DELETE, TRACE, ...) |
| `ssl_tls` | default | Audit TLS version, certificate validity and HSTS |
| `security_txt` | default | Check for security.txt (RFC 9116) presence and content |
| `tech_fingerprint` | opt-in | Fingerprint server, framework and CMS technologies |
| `robots_sitemap` | opt-in | Analyse robots.txt / sitemap.xml for info leaks and hygiene |
| `subdomains` | default | Enumerate subdomains via Certificate Transparency and DNS brute force |
| `graphql` | opt-in | Detect GraphQL endpoints with introspection enabled |
| `cve_lookup` | opt-in | Look up known CVEs for detected software versions (cve.org) |
| `jwt_audit` | default | Audit JSON Web Tokens for alg=none, weak secrets, expiry and sensitive claims |
| `csrf` | default | Detect POST/PUT/PATCH forms missing CSRF tokens (skips login/search) |
| `lfi_rfi` | default | Detect LFI/RFI via path traversal + PHP wrappers (content-verified) |
| `xxe` | default | Detect XML External Entity (XXE) via internal + external entity probes |
| `idor` | default | Detect IDOR by probing ±1 object IDs on API endpoints (TENTATIVE) |
| `clickjacking` | default | Detect missing X-Frame-Options and CSP frame-ancestors headers |
| `cache_poisoning` | default | Detect cache-poisoning via Host/X-Forwarded-Host/X-Original-URL reflection |
| `host_header_injection` | default | Detect host-header injection in password-reset / account-recovery flows |
| `ssti` | default | Detect SSTI via Jinja2/Twig/FreeMarker/ERB/Smarty syntax evaluation |
| `backup_files` | default | Detect exposed backup files (.bak, .old, .swp, ~, .orig) |
| `verbose_errors` | default | Detect stack traces, debug mode, and framework error pages in responses |
| `mass_assignment` | opt-in | Detect mass assignment by injecting role=admin, is_admin=true fields (TENTATIVE) |
| `prototype_pollution` | default | Detect client-side prototype pollution via vulnerable merge/extend patterns |
| `graphql_depth` | default | Detect GraphQL depth attacks and field-suggestion information disclosure |
| `file_upload` | default | Detect unrestricted file upload by sending a harmless test file |
| `race_condition` | opt-in | Detect race conditions by sending concurrent duplicate requests (TENTATIVE) |
| `request_smuggling` | opt-in | Detect HTTP request smuggling via CL.TE and TE.CL variants (TENTATIVE) |
| `web_cache_deception` | default | Detect Web Cache Deception via .css/.js/.png extension appending (content-verified) |
| `websocket_security` | default | Detect insecure ws:// endpoints, missing wss://, and sensitive data over WebSocket |
| `dns_security` | opt-in | DNSSEC, CAA, SPF, DMARC, DKIM record audit |
| `csp_analyzer` | default | Deep CSP parsing: unsafe directives, missing protections, report-uri |
| `waf_detect` | default | WAF detection and fingerprinting (Cloudflare, AWS, Akamai, Imperva, ModSecurity, etc.) |

## Why some plugins are opt-in

Eight plugins are excluded from the default run. They fall into three groups.

### May mutate target state

These send requests that can change data on the target. Running them against a
production system without intent could escalate a privilege, double-spend a
coupon, or smuggle a request past a proxy.

| Plugin | Why |
|---|---|
| `mass_assignment` | Injects `role=admin` / `is_admin=true` fields into write endpoints |
| `race_condition` | Fires concurrent duplicate requests to force a race |
| `request_smuggling` | Sends CL.TE and TE.CL desynchronisation probes |

### Talk to external services

A default scan contacts only the target. These reach third parties, which
leaks the fact you are auditing that host and is subject to rate limits.

| Plugin | External service |
|---|---|
| `cve_lookup` | NVD / cve.org CVE database |
| `dns_security` | Public DNS resolvers (DNSSEC, CAA, SPF, DMARC, DKIM) |

### Reconnaissance, not vulnerabilities

Useful when asked for, but they produce observations rather than findings, so
they dilute a focused scan.

| Plugin | Produces |
|---|---|
| `graphql` | GraphQL endpoint discovery and introspection state |
| `tech_fingerprint` | Server, framework, and CMS identification |
| `robots_sitemap` | `robots.txt` / `sitemap.xml` hygiene and info leaks |

> `subdomains` also performs discovery but **is** in the default set. It uses
> Certificate Transparency logs by default; pass `--no-bruteforce` to skip its
> DNS brute-force stage.

## Selecting plugins

Naming plugins explicitly replaces the default set — it does not add to it:

```bash
# Runs ONLY these three
webscan -t https://example.com --plugins headers cookies ssl_tls

# Default set plus two opt-in plugins requires listing them all;
# a preset is usually easier:
webscan -t https://example.com --preset active
```

Presets bundle plugin selections with matching scan settings:

| Preset | Plugins | Also sets |
|---|---|---|
| `quick` | Default 33 | `--min-confidence firm` |
| `safe` | Default 33 | `--crawl --safe-mode --soft-404 --no-bruteforce --min-confidence firm` |
| `full` | Default 33 + `dns_security`, `tech_fingerprint`, `robots_sitemap` | `--crawl --safe-mode --soft-404 --no-bruteforce` |
| `active` | Default 33 + `cve_lookup`, `graphql`, `mass_assignment`, `race_condition`, `request_smuggling` | — |

Presets cannot be combined with `--config`. See
[Configuration](configuration.md) for version-controlled profiles.

## Severity and confidence

Every finding carries two independent axes. Severity answers *how bad if true*;
confidence answers *how likely it is true*.

| Severity | Meaning |
|---|---|
| `critical` | Direct compromise — exposed credentials, RCE-class exposure |
| `high` | Serious exposure needing prompt attention |
| `medium` | Real weakness, exploitable under conditions |
| `low` | Minor hardening gap |
| `info` | Observation, no action implied |

| Confidence | Meaning |
|---|---|
| `firm` | Directly observed or content-verified. Very low false-positive rate. |
| `tentative` | Strong heuristic that needs manual confirmation (timing-based blind SQLi, version-based CVE matches). |
| `informational` | Best-practice note rather than a confirmed weakness. |

Filter on either axis. `--min-severity` affects the console summary;
`--min-confidence` drops findings from **all** output including report files:

```bash
# Only directly verified results, high impact or worse
webscan -t https://example.com --min-severity high --min-confidence firm
```

Plugins marked `(TENTATIVE)` in `--list-plugins` — `idor`, `mass_assignment`,
`race_condition`, `request_smuggling` — emit tentative findings by design, so
`--min-confidence firm` suppresses them entirely.

## Deduplication

Several plugins can detect the same underlying issue. For example a missing
`X-Frame-Options` header is visible to both `headers` and `clickjacking`.

Plugins tag such findings with a shared `dedup_key`. Findings are grouped by
`(url, dedup_key)`, and within a group the best report wins — ordered by
severity, then confidence, then plugin name, so the outcome never depends on
plugin scheduling. A `dedup_key` of `None` means the plugin claims no overlap
and the finding is always kept.

Nothing is silently dropped: the surviving finding lists the collapsed
duplicates under `evidence["also_reported_by"]`.

A second pass collapses **site-wide** findings across a crawl. Only findings
whose `dedup_key` starts with `site:` opt into this — a TLS or DNS issue that
belongs to the host rather than a path is reported once instead of repeated for
every crawled URL. Endpoint findings stay per-URL.

## Writing your own

See [Plugin development](plugin-development.md) for the `BasePlugin` contract,
the active-scan helpers, and how to register a plugin via entry points.
