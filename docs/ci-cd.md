# CI/CD integration

WebScan is built to fail a pipeline on the findings you care about and stay
quiet otherwise.

## Contents

- [Exit codes](#exit-codes)
- [Gating strategies](#gating-strategies)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [Docker in any runner](#docker-in-any-runner)
- [Handling credentials](#handling-credentials)
- [Practical advice](#practical-advice)

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, nothing met the failure threshold |
| `1` | A finding met the threshold, the risk gate failed, `--fail-on-new` matched, or the run could not start (no targets given, unreadable config, bad profile name) |
| `2` | Invalid command line — unknown flag, unknown plugin name, bad value for a choice flag |

A `2` means the scan never ran, so a pipeline should treat it as a
configuration error rather than a security result.

By default the threshold is **`high`**: any `critical` or `high` finding exits
`1`. Change it with `--fail-on LEVEL`.

To record results without failing the step, set `continue-on-error` (or
`|| true`) and gate on the uploaded report instead.

## Gating strategies

Pick the one that matches how noisy your target is.

### 1. Severity gate — simplest

```bash
webscan -t "$TARGET" --safe-mode --fail-on critical
```

Fails only on `critical`. Good first gate for an existing app with a backlog.

### 2. Confidence + severity — least noise

```bash
webscan -t "$TARGET" --safe-mode --min-confidence firm --fail-on high
```

Only directly verified findings can break the build.

### 3. Risk score — a trend you can hold

```bash
webscan -t "$TARGET" --safe-mode --risk-score --fail-on-risk 70
```

Fails when the 0–100 score drops below 70. Raise the bar over time.

### 4. Regression gate — best for legacy

```bash
webscan -t "$TARGET" --format json -o current --fail-on info || true
webscan diff baseline.json current.json --fail-on-new
```

An existing backlog does not break the build; only **new** findings do. Refresh
`baseline.json` deliberately, as a reviewed commit.

## GitHub Actions

### Scan and upload to Code Scanning

Findings land in the repository's Security tab.

```yaml
name: WebScan
on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * 1"   # Mondays, 06:00 UTC

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-python@v7
        with:
          python-version: "3.14"

      - name: Install WebScan
        run: python -m pip install webscan-security

      - name: Run scan
        env:
          TARGET: ${{ secrets.STAGING_URL }}
        continue-on-error: true   # let the SARIF upload surface findings
        run: |
          webscan -t "$TARGET" \
            --safe-mode \
            --min-severity high \
            --format sarif -o report

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: report.sarif
          category: webscan
```

> **Pass the target through `env`, never inline in `run:`.** Template
> interpolation happens before the shell starts, so a value containing shell
> metacharacters would be injected. The workflow shipped in
> [`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml)
> shows this pattern, plus URL validation before use.

### Fail a pull request on regressions

```yaml
      - name: Scan the deploy preview
        run: webscan -t "$PREVIEW_URL" --safe-mode --format json -o current || true

      - name: Fail on new findings
        run: webscan diff baseline.json current.json --fail-on-new
```

### Keep the report as an artifact

```yaml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: webscan-report
          path: report.*
          retention-days: 30
```

## GitLab CI

```yaml
webscan:
  image: python:3.13-slim
  stage: test
  script:
    - pip install webscan-security
    - webscan -t "$STAGING_URL" --safe-mode --min-confidence firm
        --format json html -o report --fail-on high
  artifacts:
    when: always
    paths:
      - report.json
      - report.html
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Security scan') {
      steps {
        sh 'python -m pip install --user webscan-security'
        sh '''
          webscan -t "$STAGING_URL" \
            --safe-mode --risk-score --fail-on-risk 70 \
            --format json html -o report
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'report.*', allowEmptyArchive: true
    }
  }
}
```

## Docker in any runner

No Python setup step needed:

```bash
docker run --rm -v "$PWD/reports:/reports" \
  ghcr.io/lutzashl290788-cell/webscan \
  -t "$TARGET" --safe-mode --format sarif -o /reports/report
```

The image runs as uid 10001, so the mounted directory must be writable by that
user (or use `--user "$(id -u):$(id -g)"`).

## Handling credentials

Never commit cookies, tokens, or Basic-auth pairs.

- Store them as CI secrets and pass them via environment variables.
- Command-line arguments are visible in the process list — on a shared runner,
  prefer a config file written at runtime with restrictive permissions.
- Config files **cannot** carry credentials by design; see
  [Configuration](configuration.md#supported-keys).
- Add `--anonymize` when a report is published anywhere beyond the team.

## Practical advice

- **Scan staging, not production.** Active checks send real requests.
- **Use `--safe-mode` on shared infrastructure** so a scan does not look like
  an attack to your own WAF.
- **Schedule deep scans; keep PR scans shallow.** A nightly `--crawl --depth 3`
  and a per-PR header/cookie/TLS pass is a good split.
- **Start with a loose gate and tighten it.** A gate that always fails gets
  disabled.
- **Keep the baseline in version control** so changing it is a reviewed act.
