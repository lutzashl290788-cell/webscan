# Reports

WebScan writes six formats. Pick a base path with `-o` and one or more formats
with `--format`; extensions are appended automatically.

```bash
webscan -t https://example.com --format json html sarif -o reports/example
# -> reports/example.json, reports/example.html, reports/example.sarif
```

The default is `--format json md`. Without `-o` no files are written and only
the console summary is printed.

## Contents

- [Choosing a format](#choosing-a-format)
- [JSON](#json)
- [JSON Lines](#json-lines)
- [Markdown](#markdown)
- [HTML](#html)
- [SARIF](#sarif)
- [CSV](#csv)
- [Anonymising a report](#anonymising-a-report)
- [Comparing two reports](#comparing-two-reports)
- [Risk score and compliance](#risk-score-and-compliance)
- [Webhooks](#webhooks)
- [Local dashboard](#local-dashboard)

## Choosing a format

| Format | Flag | Best for |
|---|---|---|
| JSON | `--format json` | Archives, APIs, custom tooling |
| JSON Lines | `--format jsonl` | `jq`, streaming, line-oriented pipelines |
| Markdown | `--format md` | Pull requests and human review |
| HTML | `--format html` | Offline stakeholder reports |
| SARIF | `--format sarif` | GitHub Code Scanning, IDE integrations |
| CSV | `--format csv` | Spreadsheets, Jira, data imports |

## JSON

One nested document covering the whole scan. This is the format to archive and
the one `webscan diff` consumes.

```json
{
  "scan_started": "2026-09-03T10:00:00Z",
  "scan_finished": "2026-09-03T10:00:07Z",
  "total_findings": 1,
  "targets": [
    {
      "target": "https://example.com",
      "findings": [
        {
          "plugin": "headers",
          "title": "Missing Strict-Transport-Security header",
          "severity": "medium",
          "description": "The response does not set HSTS.",
          "url": "https://example.com/",
          "evidence": {
            "header": "Strict-Transport-Security",
            "observed": null
          },
          "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
          "confidence": "firm",
          "dedup_key": "site:hsts"
        }
      ],
      "errors": [],
      "scanned_at": "2026-09-03T10:00:07Z"
    }
  ]
}
```

`errors` collects per-target failures (timeouts, DNS problems) so a partial
scan is still an honest report rather than a silently short one.

## JSON Lines

One self-contained object per finding, ordered by severity within each target.
Each line repeats the target and scan context, so no tree walking is needed:

```bash
webscan -t https://example.com --format jsonl -o findings

# Critical findings only
jq 'select(.severity == "critical")' findings.jsonl

# Count by plugin
jq -r .plugin findings.jsonl | sort | uniq -c | sort -rn

# Title and URL as a table
jq -r '[.severity, .plugin, .url] | @tsv' findings.jsonl
```

A scan with no findings produces an empty file (zero lines), which is valid
JSONL.

## Markdown

A readable summary with severity counts and per-finding detail — designed to be
pasted into a pull request or an incident ticket.

```bash
webscan -t https://example.com --format md -o reports/pr-42
```

## HTML

A self-contained dashboard: severity breakdown, filtering, evidence, and
remediation. No external assets, so it opens offline and can be sent to someone
with no WebScan installation.

Pair with `--anonymize` before sharing outside your team.

## SARIF

Static Analysis Results Interchange Format — the format GitHub Code Scanning
ingests. Upload it and findings appear in the repository's Security tab,
annotated on the relevant lines where a location is known.

```bash
webscan -t https://example.com --format sarif -o report
```

See [CI/CD integration](ci-cd.md) for the upload workflow.

## CSV

Flat rows for spreadsheets and issue-tracker imports:

```csv
target,plugin,severity,confidence,title,url,description,remediation,evidence
https://example.com,headers,medium,firm,Missing Strict-Transport-Security header,https://example.com/,The response does not set HSTS.,Add: Strict-Transport-Security: max-age=31536000; includeSubDomains,"{""header"": ""Strict-Transport-Security"", ""observed"": null}"
```

Values that could be interpreted as formulas by a spreadsheet are sanitised, so
opening a report cannot execute an injected formula.

## Anonymising a report

`--anonymize` rewrites reports before they are written, stripping:

- Local filesystem paths
- Your hostname and username
- Private IP addresses

```bash
webscan -t https://example.com --format html sarif -o public-report --anonymize
```

Reports still contain findings about the target, including URLs and response
evidence. Anonymising protects **your** environment, not the target's — review
before publishing.

## Comparing two reports

`webscan diff` compares two JSON reports and classifies findings as new, fixed,
or changed:

```bash
webscan diff baseline.json current.json
webscan diff baseline.json current.json --fail-on-new   # exit 1 if anything is new
```

This turns a security regression into a pipeline failure without requiring a
clean baseline — only *new* findings break the build.

## Risk score and compliance

```bash
webscan -t https://example.com --risk-score --compliance
```

- `--risk-score` prints a 0–100 score (100 = clean) with an A–F grade.
- `--compliance` maps findings to OWASP Top 10 2021 categories and shows which
  categories are affected and which are clean.
- `--fail-on-risk N` exits 1 when the score falls below `N`.

## Webhooks

Send a summary to chat after a scan. The type is auto-detected from the URL
(Slack, Discord, Teams, or a generic HTTP endpoint):

```bash
webscan -t https://example.com --webhook-url "$SLACK_WEBHOOK_URL"
```

## Local dashboard

With the `serve` extra installed, browse past scans locally:

```bash
python -m pip install 'webscan-security[serve]'
webscan serve
```

Open `http://127.0.0.1:8000` to launch a scan, revisit previous ones, and
filter findings by severity, confidence, plugin, or free-text query.

History is stored in `~/.webscan/history.db` and is **never uploaded**. Move it
with `--history-db /path/to/history.db` or `WEBSCAN_HISTORY_DB`. Bind elsewhere
with `--host` and `--port`; the default binds to loopback only.
