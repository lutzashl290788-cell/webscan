# Troubleshooting

Common problems, what causes them, and what to do.

## Contents

- [Installation](#installation)
- [Running a scan](#running-a-scan)
- [Too many or too few findings](#too-many-or-too-few-findings)
- [Reports](#reports)
- [CI pipelines](#ci-pipelines)
- [Dashboard and history](#dashboard-and-history)
- [Still stuck](#still-stuck)

## Installation

### `webscan: command not found`

The package installed but its scripts directory is not on your `PATH`. Use the
module form, which always works:

```bash
python -m webscan --version
```

To fix the `PATH`, either activate the virtual environment you installed into,
or install with `pipx install webscan-security`, which manages this for you.

### `ERROR: Cannot uninstall PyYAML ... RECORD file not found`

A system package manager installed PyYAML outside pip's control. Install into a
virtual environment instead of the system interpreter:

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install webscan-security
```

### `--ai-triage` / `--ai-summary` do nothing

They are **silently skipped** when the `ai` extra or the API key is missing, so
scripts using them still run on a base install. Enable them with:

```bash
python -m pip install 'webscan-security[ai]'
export ANTHROPIC_API_KEY=...
```

### `webscan serve` fails to start

The dashboard needs the `serve` extra:

```bash
python -m pip install 'webscan-security[serve]'
```

## Running a scan

### Exit code 2 and a usage message

Code `2` means the command line itself was rejected — an unknown flag, an
unknown plugin name, or a bad value for a choice flag. The scan never ran. Check
the name against `webscan --list-plugins`.

### The scan exits 1 but I only see low-severity findings

The default failure threshold is `high`, and it applies to **all** findings,
including ones filtered out of the console summary by `--min-severity`. Filtering
the display does not change the exit code. Set the threshold explicitly:

```bash
webscan -t https://example.com --min-severity high --fail-on critical
```

### Everything times out

Raise the per-request timeout and slow down. Some hosts throttle aggressively:

```bash
webscan -t https://example.com --timeout 30 --concurrency 3 --rate-limit 2
```

### The target blocks or rate-limits me

You are being detected as a scanner. Start polite:

```bash
webscan -t https://example.com --safe-mode
```

If your own WAF is the obstacle during authorised testing, allowlist the
scanning host rather than escalating evasion. `--stealth` exists for authorised
engagements where detection is part of the test — it is not a way around
someone else's protections.

### TLS errors on a host with a valid certificate

WebScan skips certificate verification **by default** so it can audit
self-signed and expired-certificate hosts. If you want a verification failure to
be visible, pass `--strict-ssl`.

Note that most built-in plugins issue their requests with verification disabled
per request, so `--strict-ssl` mainly affects the engine's own connections
rather than every plugin probe. Use the `ssl_tls` plugin's findings to assess a
certificate.

### Authenticated areas return the login page

Session-aware scanning needs credentials that outlive the handshake:

```bash
# Reuse a browser session
webscan -t https://app.example.com --cookie "session=abc123"

# Bearer token
webscan -t https://api.example.com --header "Authorization: Bearer $TOKEN"

# Form login
webscan -t https://app.example.com \
  --login-url https://app.example.com/login \
  --login-data "username=admin&password=secret"
```

If the app rotates CSRF tokens on every request, capture a cookie from a live
browser session instead of using `--login-url`.

### Crawling finds nothing

- The site is client-rendered: WebScan parses server HTML, not executed
  JavaScript. Feed it a URL list with `-f targets.txt`.
- `robots.txt` disallows the paths. During authorised testing, `--ignore-robots`.
- `--scope` or `--exclude` is narrower than you think — a `--scope` value must
  match the host.

## Too many or too few findings

### Too many, and they look wrong

In order of effectiveness:

```bash
# 1. Drop unverified findings entirely
webscan -t https://example.com --min-confidence firm

# 2. Suppress soft-404s on sites that answer 200 for everything
webscan -t https://example.com --soft-404

# 3. Both, plus an impact floor
webscan -t https://example.com --min-confidence firm --min-severity medium

# 4. Or just use the preset that bundles them
webscan -t https://example.com --preset safe
```

### Too few — a check I expected did not run

Eight plugins are excluded from the default run. `cve_lookup`, `graphql`,
`dns_security`, `tech_fingerprint`, `robots_sitemap`, `mass_assignment`,
`race_condition`, and `request_smuggling` must be requested:

```bash
webscan -t https://example.com --plugins graphql cve_lookup
webscan -t https://example.com --preset active     # default set + active opt-ins
```

Remember that naming plugins **replaces** the default set rather than adding to
it. See the [plugin reference](plugins.md#why-some-plugins-are-opt-in).

### A finding disappeared between runs

Check whether `--min-confidence firm` is in play. Plugins marked `(TENTATIVE)`
in `--list-plugins` — `idor`, `mass_assignment`, `race_condition`,
`request_smuggling` — emit tentative findings only, so `firm` filtering removes
them completely.

Deduplication is the other cause: an issue two plugins can both see is reported
once, by whichever plugin's report is most severe. The others are listed in that
finding's `evidence["also_reported_by"]`.

## Reports

### No report files were written

`-o` is required. Without it, results only go to the console:

```bash
webscan -t https://example.com --format json html -o reports/example
```

Do not add the extension yourself — it is appended per format.

### The JSONL file is empty

That is a valid result: zero findings means zero lines.

### A config file setting is ignored

Only a fixed set of keys is honoured; anything else is dropped silently. Check
the key against [Supported keys](configuration.md#supported-keys), and note that
keys use the underscore form (`safe_mode`, not `safe-mode`). Targets,
credentials, and `min_confidence` cannot be set from a config file at all.

Also remember the precedence: an explicit CLI flag always wins over the profile.

### `--preset` and `--config` together fail

That combination is rejected by design. Presets are fixed bundles; config files
are yours to shape. Move the preset's settings into a profile if you need both.

## CI pipelines

### The build fails on a pre-existing backlog

Gate on regressions instead of absolute state:

```bash
webscan -t "$TARGET" --format json -o current --fail-on info || true
webscan diff baseline.json current.json --fail-on-new
```

### SARIF upload succeeds but nothing appears in the Security tab

- The job needs `security-events: write` permission.
- Uploads from forked-repository pull requests are restricted by GitHub.
- A scan with zero findings produces a valid SARIF file with no results.

### Scans behave differently in CI than locally

Usually the runner's egress: a proxy, an allowlist, or DNS. Confirm the target
resolves and responds from inside the runner before blaming the scanner, and
route through your proxy explicitly with `--proxy` if one is required.

## Dashboard and history

Scan history lives in `~/.webscan/history.db` and is never uploaded. Move it
with `--history-db /path/to/history.db` or the `WEBSCAN_HISTORY_DB` environment
variable. Deleting the file resets history; nothing else depends on it.

`webscan serve` binds to `127.0.0.1:8000` by default. Change it with `--host`
and `--port` — but the reports contain evidence from your targets, so do not
bind it to a public interface.

## Still stuck

1. Re-run with `-v` for per-finding output.
2. Confirm the version: `webscan --version`.
3. Search [existing issues](https://github.com/lutzashl290788-cell/webscan/issues).
4. Open a [bug report](https://github.com/lutzashl290788-cell/webscan/issues/new/choose)
   with the command, the full output, and your environment.

Found a vulnerability **in WebScan itself**? Do not open an issue — follow
[SECURITY.md](../SECURITY.md).
