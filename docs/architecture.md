# Architecture

A scan is a pipeline: normalise targets, optionally crawl, run plugins
concurrently against each URL, verify and deduplicate findings, then render.

## Contents

- [Module map](#module-map)
- [The scan pipeline](#the-scan-pipeline)
- [Concurrency model](#concurrency-model)
- [The plugin registry](#the-plugin-registry)
- [False-positive controls](#false-positive-controls)
- [Design constraints](#design-constraints)

## Module map

```text
webscan/
├── cli.py           CLI parsing, presets, safety notice, subcommands
├── api.py           Public library facade: scan() / scan_sync()
├── engine.py        Async orchestration, session setup, deduplication
├── crawler.py       Breadth-first URL and form discovery
├── net.py           Proxy, rate limiting, User-Agent, stealth
├── auth.py          Cookie, header, Basic, and form-login sessions
├── registry.py      Plugin registry — the single source of truth
├── models.py        Finding, Severity, Confidence, ScanReport dataclasses
├── reporter.py      Six output formats plus the terminal summary
├── risk.py          0-100 score and A-F grade
├── compliance.py    OWASP Top 10 2021 mapping
├── diff.py          New / fixed / changed report comparison
├── anonymize.py     Redaction for shareable reports
├── explanations.py  Plain-language text for --explain
├── autofix.py       Copy-paste remediation for --suggest-fixes
├── notify.py        Slack / Discord / Teams / HTTP webhooks
├── ai.py            Optional Claude triage and summary ([ai] extra)
├── history.py       Local scan history store
├── server.py        FastAPI backend for `webscan serve` ([serve] extra)
├── dashboard.py     Dashboard rendering for the local server
├── retry.py         Retry and backoff policy
├── utils/           HTML and HTTP helpers
└── plugins/         41 built-in checks + BasePlugin + shared helpers
```

Runtime dependencies are deliberately minimal — `aiohttp` and `PyYAML`.
Everything else is an optional extra, so the base install stays small and its
supply chain stays reviewable.

## The scan pipeline

```text
targets / file
      |
      v
normalise + deduplicate ---- optional crawl ----> discovered URLs
      |
      v
async engine  ---> passive plugins  ---> active plugins (selected / opt-in)
      |
      v
content verification + confidence + severity
      |
      +--> deduplication (per-URL, then site-wide)
      |
      +--> terminal summary
      +--> JSON / JSONL / Markdown / HTML / SARIF / CSV
      +--> risk score / compliance / diff / webhook
```

**1. Target normalisation** — bare hosts get `https://`, trailing slashes are
stripped, and duplicates collapse. The CLI and the Python API share this step,
so both behave identically.

**2. Crawl (optional)** — `crawler.py` walks breadth-first from each seed,
bounded by `--depth`, `--max-urls`, `--scope`, and `--exclude`, and respects
`robots.txt` unless `--ignore-robots` is passed. Forms are collected too, so
POST-based checks have somewhere to aim.

**3. Session construction** — `engine.py` builds one shared
`aiohttp.ClientSession` carrying the proxy, auth, headers, cookies, timeouts,
TLS context, and connection limits. Every plugin receives this session, so the
operator's safety flags apply everywhere at once.

**4. Plugin execution** — plugins run concurrently against each target, bounded
by a semaphore. A plugin that raises is contained: the failure is recorded in
`TargetResult.errors` and the rest of the scan continues.

**5. Verification and scoring** — plugins verify against response content
before reporting, and tag each finding with a severity and a confidence.

**6. Deduplication** — findings sharing a `(url, dedup_key)` collapse to the
most severe report; a second pass collapses `site:`-keyed findings across the
whole crawl.

**7. Rendering** — `reporter.py` turns one `ScanReport` into any of the six
formats plus the terminal summary. Risk, compliance, diff, and webhook layers
read the same report object.

## Concurrency model

- One event loop, one shared session, one connector pool.
- `--concurrency N` (default 10) bounds targets in flight via a semaphore; the
  connector allows `N` connections per host and `N × 8` overall.
- `--rate-limit` and `--delay` (with optional `--random-delay` jitter) throttle
  request issue rate.
- `--safe-mode` lowers concurrency, caps the rate, respects `robots.txt`, and
  sends an honest User-Agent.
- `--stealth` goes further: a single in-flight connection, at least 2s between
  requests, rotating User-Agents, and spoofed forwarding headers — so the
  traffic reads as one client browsing rather than a burst of parallel probes.

## The plugin registry

`registry.py` is the single source of truth. It defines `_BUILTIN_PLUGINS`,
merges in any entry-point plugins, and derives:

- `ALL_PLUGINS` — everything available
- `OPT_IN_PLUGINS` — the 8 excluded from a default run
- `DEFAULT_PLUGINS` — the remaining 33, in registry order

Both `cli.py` and `api.py` build their plugin lists from here, so the CLI and
the library can never disagree about what exists.

Discovery is hardened in two ways: a third-party entry point **cannot shadow a
built-in** (a collision is reported on stderr and skipped), and a plugin that
fails to import is skipped rather than aborting startup.

## False-positive controls

The project's premise is signal over noise. Four mechanisms carry that:

| Mechanism | What it prevents |
|---|---|
| **Content verification** | Reporting a file that exists by status code but whose content does not match its name |
| **Soft-404 calibration** (`--soft-404`) | Findings on sites that answer `200` for every path |
| **Confidence levels** | Heuristics being presented with the same weight as observed facts |
| **Deduplication** | One issue counted several times because several plugins can see it |

## Design constraints

These hold across the codebase and are worth knowing before proposing changes:

- **A plugin never raises.** Errors are values, collected per target.
- **A default run touches only the target.** External lookups are opt-in.
- **A default run does not mutate state.** State-changing checks are opt-in.
- **Plugins do not create sessions.** The engine owns the session so safety
  flags cannot be bypassed.
- **The registry is the only place plugin identity is defined.**
- **Reports are dataclasses.** Rendering is a separate layer that reads them.
