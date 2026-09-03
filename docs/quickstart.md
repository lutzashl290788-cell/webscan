# Quickstart

From zero to a reviewable report in about five minutes.

> **Authorisation first.** Scan only systems you own or have explicit written
> permission to test. See [Legal](../README.md#legal).

## Contents

- [1. Install](#1-install)
- [2. Your first scan](#2-your-first-scan)
- [3. Read the output](#3-read-the-output)
- [4. Save a report](#4-save-a-report)
- [5. Cut the noise](#5-cut-the-noise)
- [6. Crawl before scanning](#6-crawl-before-scanning)
- [7. Score and gate](#7-score-and-gate)
- [Where to go next](#where-to-go-next)

## 1. Install

```bash
python -m pip install webscan-security
webscan --version
```

Details and extras: [Installation](installation.md).

## 2. Your first scan

Start with `--safe-mode`. It lowers concurrency, caps the request rate,
respects `robots.txt`, and sends an honest User-Agent — the polite default for
a first look at a live system.

```bash
webscan -t https://example.com --safe-mode --explain
```

`--explain` prints a plain-language paragraph under each finding, which is the
fastest way to learn what the checks actually mean.

Prefer a bundled configuration? The `quick` preset runs the default plugin set
and keeps only directly verified findings:

```bash
webscan -t https://example.com --preset quick
```

## 3. Read the output

Every finding carries two independent ratings:

- **Severity** — how bad it is if real: `critical`, `high`, `medium`, `low`, `info`
- **Confidence** — how sure the scanner is: `firm`, `tentative`, `informational`

A `firm` finding was directly observed or content-verified. A `tentative` one
is a strong heuristic that still needs a human to confirm. Both axes appear on
every finding so you can triage by impact and by certainty separately.

Full explanation: [Severity and confidence](plugins.md#severity-and-confidence).

## 4. Save a report

Pass a base path with `-o` and one or more formats. The extension is added for
you:

```bash
webscan -t https://example.com \
  --safe-mode \
  --format json html md \
  -o reports/example
```

This writes `reports/example.json`, `reports/example.html`, and
`reports/example.md`. HTML reports are self-contained and can be shared with
someone who has no WebScan installation.

Sharing outside your team? Add `--anonymize` to strip local paths, your
hostname and username, and private IP addresses first.

All six formats: [Reports](reports.md).

## 5. Cut the noise

Three flags do most of the work:

```bash
# Only directly verified findings
webscan -t https://example.com --min-confidence firm

# Only high-impact findings in the summary
webscan -t https://example.com --min-severity high

# Suppress soft-404 false positives on sites that answer 200 for everything
webscan -t https://example.com --soft-404
```

`--min-confidence` drops findings from **all** output, including report files.
`--min-severity` filters only the console summary.

## 6. Crawl before scanning

By default WebScan audits exactly the URLs you give it. Add `--crawl` to
discover routes first:

```bash
webscan -t https://example.com --crawl --depth 2 --max-urls 100 --safe-mode
```

Crawling respects `robots.txt` unless you pass `--ignore-robots`. Restrict the
crawl with `--scope` and `--exclude` to keep it inside your own perimeter.

## 7. Score and gate

For a single number to track over time:

```bash
webscan -t https://example.com --risk-score --compliance
```

`--risk-score` prints a 0–100 score with an A–F grade; `--compliance` maps
findings to OWASP Top 10 2021 categories.

WebScan exits with code `1` when a finding is `critical` or `high`, which is
enough to fail a pipeline step. Tighten or relax it with `--fail-on LEVEL`, or
gate on the score with `--fail-on-risk N`:

```bash
webscan -t https://staging.example.com --format sarif -o report --fail-on-risk 70
```

Pipeline recipes: [CI/CD integration](ci-cd.md).

## Where to go next

| I want to... | Read |
|---|---|
| Understand what each check does | [Plugin reference](plugins.md) |
| Keep settings under version control | [Configuration](configuration.md) |
| Pick the right output format | [Reports](reports.md) |
| Fail a build on regressions | [CI/CD integration](ci-cd.md) |
| Call WebScan from Python | [Python API](python-api.md) |
| Fix an error I hit | [Troubleshooting](troubleshooting.md) |
