# WebScan documentation

Content-verified web security auditing — reference documentation for the
[WebScan](../README.md) scanner.

## Start here

| Guide | For |
|---|---|
| [Installation](installation.md) | pip, extras, Docker, pipx, verifying the install |
| [Quickstart](quickstart.md) | First scan to first report, in about five minutes |

## Using WebScan

| Guide | Covers |
|---|---|
| [Plugin reference](plugins.md) | All 41 checks, why 8 are opt-in, severity and confidence, deduplication |
| [Configuration](configuration.md) | YAML profiles, precedence, every supported key, environment variables |
| [Reports](reports.md) | The six output formats, anonymising, diffing, risk scoring, webhooks, dashboard |
| [CI/CD integration](ci-cd.md) | Exit codes, gating strategies, GitHub Actions, GitLab, Jenkins, Docker |
| [Troubleshooting](troubleshooting.md) | Install problems, noisy results, missing checks, CI issues |

## Extending WebScan

| Guide | Covers |
|---|---|
| [Python API](python-api.md) | `scan()`, the report dataclasses, rendering, the registry |
| [Plugin development](plugin-development.md) | The `BasePlugin` contract, helpers, testing, publishing a plugin |
| [Architecture](architecture.md) | Module map, scan pipeline, concurrency, design constraints |

## Project

| Document | Purpose |
|---|---|
| [README](../README.md) | Overview, feature tour, CLI reference |
| [CONTRIBUTING](../CONTRIBUTING.md) | Dev setup, tests, submitting changes |
| [SECURITY](../SECURITY.md) | Reporting a vulnerability, the scan security model |
| [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) | Community standards |
| [CHANGELOG](../CHANGELOG.md) | Release history |

## Common tasks

| I want to... | Go to |
|---|---|
| Run my first scan safely | [Quickstart §2](quickstart.md#2-your-first-scan) |
| Understand a finding's severity vs confidence | [Plugins](plugins.md#severity-and-confidence) |
| Cut false positives | [Troubleshooting](troubleshooting.md#too-many-and-they-look-wrong) |
| Enable an opt-in check | [Plugins](plugins.md#selecting-plugins) |
| Share a report outside my team | [Reports](reports.md#anonymising-a-report) |
| Fail a build only on new findings | [CI/CD](ci-cd.md#4-regression-gate--best-for-legacy) |
| Scan behind a login | [Troubleshooting](troubleshooting.md#authenticated-areas-return-the-login-page) |
| Call WebScan from Python | [Python API](python-api.md#running-a-scan) |
| Write my own check | [Plugin development](plugin-development.md#a-minimal-plugin) |

---

> **Authorised testing only.** Scan only systems you own or have explicit
> written permission to test. See [Legal](../README.md#legal).
