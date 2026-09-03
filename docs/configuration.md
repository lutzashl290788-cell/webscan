# Configuration

Long command lines do not survive code review. A YAML config file lets a team
keep scan settings under version control and select them by name.

## Contents

- [Precedence](#precedence)
- [File shapes](#file-shapes)
- [Supported keys](#supported-keys)
- [Worked example](#worked-example)
- [Presets vs config files](#presets-vs-config-files)
- [Environment variables](#environment-variables)
- [Target lists](#target-lists)

## Precedence

Settings resolve in this order, highest first:

1. **Explicit command-line flags**
2. **The selected config profile**
3. **Built-in defaults**

So a profile can set `concurrency: 30` and a one-off run can still override it:

```bash
webscan -t https://example.com --config webscan.yml --profile deep --concurrency 5
```

## File shapes

Two shapes are accepted.

### Flat — a single implicit profile

```yaml
plugins: [headers, cookies, ssl_tls]
concurrency: 20
timeout: 15
format: [json, sarif]
output: ./reports/scan
```

```bash
webscan -t https://example.com --config webscan.yml
```

Passing `--profile` against a flat file is an error.

### Named profiles

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
```

If the file defines `profiles:` you must select one with `--profile`, unless a
profile literally named `default` exists — that one is used when `--profile` is
omitted. Naming a profile that does not exist fails with the list of available
names.

## Supported keys

Only these keys are honoured. Anything else in the file is **ignored silently**
— a config file cannot inject arbitrary settings into a run.

| Key | Type | Equivalent flag |
|---|---|---|
| `plugins` | list of strings | `--plugins` |
| `concurrency` | integer | `-c`, `--concurrency` |
| `timeout` | integer (seconds) | `--timeout` |
| `format` | list of strings | `--format` |
| `output` | string (base path) | `-o`, `--output` |
| `crawl` | boolean | `--crawl` |
| `depth` | integer | `--depth` |
| `max_urls` | integer | `--max-urls` |
| `scope` | string (host) | `--scope` |
| `exclude` | list of strings | `--exclude` |
| `min_severity` | string | `--min-severity` |
| `fail_on` | string | `--fail-on` |
| `safe_mode` | boolean | `--safe-mode` |
| `delay` | float (seconds) | `--delay` |
| `rate_limit` | number | `--rate-limit` |
| `retries` | integer | `--retries` |
| `retry_backoff` | float (seconds) | `--retry-backoff` |
| `verbose` | boolean | `-v`, `--verbose` |
| `quiet` | boolean | `-q`, `--quiet` |
| `anonymize` | boolean | `--anonymize` |

Keys use the flag's underscore form (`safe_mode`, not `safe-mode`).

> **Not configurable from a file:** targets, credentials, and
> `min_confidence`. Targets stay on the command line (or in a
> [target list](#target-lists)) so a committed file can never silently point a
> scan at the wrong host, and credentials stay out of version control by
> construction.

## Worked example

A `webscan.yml` covering three stages of a team's workflow:

```yaml
profiles:
  # Fast feedback on every pull request.
  default:
    plugins: [headers, cookies, ssl_tls, csrf, clickjacking, secrets]
    concurrency: 20
    timeout: 10
    safe_mode: true
    format: [sarif]
    output: ./reports/pr
    fail_on: high

  # Nightly run against staging, with discovery.
  nightly:
    crawl: true
    depth: 3
    max_urls: 300
    scope: staging.example.com
    exclude: ["/logout", "/admin/delete"]
    safe_mode: true
    rate_limit: 5
    format: [json, html]
    output: ./reports/nightly
    anonymize: true

  # Pre-release deep audit, authorised window only.
  release:
    plugins:
      [headers, cookies, ssl_tls, csrf, clickjacking, secrets,
       sql_injection, xss, ssrf, lfi_rfi, ssti, xxe, idor, cve_lookup]
    crawl: true
    depth: 4
    concurrency: 10
    retries: 3
    retry_backoff: 1.0
    format: [json, html, sarif, csv]
    output: ./reports/release
```

```bash
webscan -t https://staging.example.com --config webscan.yml                      # default
webscan -t https://staging.example.com --config webscan.yml --profile nightly
webscan -t https://staging.example.com --config webscan.yml --profile release
```

## Presets vs config files

| | Preset (`--preset`) | Config file (`--config`) |
|---|---|---|
| Where it lives | Built into WebScan | Your repository |
| Customisable | No | Yes |
| Best for | Ad-hoc runs, first look | Team workflows, CI |

**The two cannot be combined.** `--preset` with `--config` is rejected. Presets
are described in the [plugin reference](plugins.md#selecting-plugins).

## Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | `--ai-triage`, `--ai-summary` | API key for the optional AI layer (`[ai]` extra) |
| `WEBSCAN_AI_MODEL` | `--ai-triage`, `--ai-summary` | Override the Claude model used |
| `WEBSCAN_HISTORY_DB` | `webscan serve` | Path to the local scan-history database (default `~/.webscan/history.db`) |

## Target lists

Targets are not part of a config file. For more than a handful, use a
plain-text file — one URL per line, `#` starts a comment:

```text
# Public marketing surface
https://example.com
https://www.example.com

# Application
https://app.example.com/login
```

```bash
webscan -f targets.txt --config webscan.yml --profile nightly
```
