# Security Policy

WebScan is a security tool, so it is held to the standard it audits for. This
document covers two separate things:

1. [Reporting a vulnerability **in WebScan itself**](#reporting-a-vulnerability)
2. [The security model of running a scan](#security-model)

---

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub Security Advisories:

**[Report a vulnerability →](https://github.com/lutzashl290788-cell/webscan/security/advisories/new)**

That form creates a private advisory visible only to you and the maintainers.

### What to include

A report is actionable when it answers these:

| Field | Detail |
|---|---|
| Affected version | Output of `webscan --version`, or the commit SHA |
| Component | e.g. `webscan/net.py`, the `serve` dashboard, a specific plugin |
| Impact | What an attacker gains — RCE, credential disclosure, SSRF, path traversal |
| Reproduction | Minimal command or script, plus any input files |
| Attacker model | Who must control what: the scan target, a config file, a report, the network |

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of the report | 72 hours |
| Initial assessment and severity | 7 days |
| Fix or documented mitigation | 30 days for high/critical, best effort otherwise |
| Public advisory and release | Coordinated with you, after the fix ships |

We credit reporters in the advisory and the changelog unless you ask us not to.
Please give us a chance to ship a fix before disclosing publicly.

### Supported versions

| Version | Supported |
|---|---|
| 2.8.x | Yes — current release line |
| 2.7.x and earlier | No — upgrade to 2.8.x |

Fixes land on the latest minor release. There are no long-term support
branches.

### In scope

- Code execution, injection, or path traversal triggered by a **scan target's
  response** — a hostile server should never be able to compromise the operator.
- Leakage of credentials passed via `--cookie`, `--header`, `--basic-auth`, or
  `--login-data` into reports, logs, or outbound requests.
- `--anonymize` failing to redact data it claims to redact.
- Vulnerabilities in the `serve` dashboard (`webscan serve`), including its
  local history database.
- A third-party plugin being able to shadow or hijack a built-in plugin.
- Deserialisation or parsing flaws in config, target, or report handling.

### Out of scope

- Findings produced **by** WebScan about a third-party site. Report those to
  that site's owner.
- False positives and false negatives in a plugin — those are ordinary
  [bug reports](https://github.com/lutzashl290788-cell/webscan/issues/new/choose).
- Results from scanning a target you are not authorised to test.
- Vulnerabilities in a dependency with no exploitable path through WebScan.
  Report those upstream; open a normal issue here if a version bump is needed.
- The scanner sending requests a target considers hostile. That is the tool
  working as designed under operator control.

---

## Security model

### Authorisation is the operator's responsibility

WebScan sends requests that many jurisdictions treat as unauthorised access
when performed without permission. Scan only what you own or hold explicit
written permission to test. See [Legal](README.md#legal).

### Default posture

- Active checks that may **mutate state** (`mass_assignment`, `race_condition`,
  `request_smuggling`) are excluded from the default run and must be enabled
  explicitly.
- Checks that call **external services** (`cve_lookup`, `dns_security`) are also
  opt-in, so a default scan talks only to the target.
- `--safe-mode` lowers concurrency, caps the request rate, respects
  `robots.txt`, and sends an honest User-Agent.
- TLS verification is **off** by default, so hosts with expired or self-signed
  certificates can still be audited. Use `--strict-ssl` when a valid
  certificate is expected and a failure is itself a finding.

### Handling credentials and reports

- Credentials passed on the command line are visible in your shell history and
  in the process list. Prefer a config file with restrictive permissions, or a
  short-lived token.
- Reports embed request and response evidence, which can include session
  identifiers and internal hostnames. Treat them as sensitive artefacts.
- Use `--anonymize` to strip local paths, hostname/username, and private IPs
  before sharing a report outside your team.
- Scan history from `webscan serve` is stored locally in `~/.webscan/history.db`
  and is never uploaded. Override the location with `--history-db` or
  `WEBSCAN_HISTORY_DB`.

### Supply chain

- Runtime dependencies are deliberately minimal: `aiohttp` and `PyYAML`.
- Docker images are built from digest-pinned base images and run as an
  unprivileged user (uid 10001).
- Third-party plugins registered under the `webscan.plugins` entry-point group
  **cannot shadow a built-in plugin**; a colliding name is reported on stderr
  and skipped. Only install plugins you trust — they run with your credentials.
