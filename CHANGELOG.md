# Changelog

All notable changes to WebScan are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/lutzashl290788-cell/webscan/compare/v1.3...HEAD
[1.3.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.2...v1.3
[1.2.0]: https://github.com/lutzashl290788-cell/webscan/compare/v1.1...v1.2
[1.1.0]: https://github.com/lutzashl290788-cell/webscan/releases/tag/v1.1
