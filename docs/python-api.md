# Python API

WebScan is a library as well as a CLI. `webscan.scan()` is the supported entry
point for embedding it in recon pipelines, notebooks, or CI glue — no shelling
out and no reaching into private internals.

## Contents

- [Public surface](#public-surface)
- [Running a scan](#running-a-scan)
- [Blocking callers](#blocking-callers)
- [Full parameter reference](#full-parameter-reference)
- [Working with the report](#working-with-the-report)
- [Rendering reports](#rendering-reports)
- [Progress callbacks](#progress-callbacks)
- [Inspecting the registry](#inspecting-the-registry)
- [Error handling](#error-handling)

## Public surface

Everything exported from the top-level package is stable API:

```python
import webscan

webscan.scan            # async scan entry point
webscan.scan_sync       # blocking wrapper
webscan.ScanReport      # top-level report dataclass
webscan.TargetResult    # per-target results
webscan.Finding         # a single finding
webscan.Severity        # critical | high | medium | low | info
webscan.Confidence      # firm | tentative | informational
webscan.Reporter        # renders a report in any format
webscan.ALL_PLUGINS     # dict[str, type[BasePlugin]]
webscan.DEFAULT_PLUGINS # list[str] — the default run
webscan.OPT_IN_PLUGINS  # frozenset[str] — excluded by default
webscan.__version__
```

## Running a scan

```python
import asyncio
import webscan

report = asyncio.run(webscan.scan(
    ["https://example.com"],
    plugins=["headers", "cookies", "config_files"],
    soft_404=True,
))

for target in report.targets:
    for finding in target.findings:
        print(finding.severity.value, finding.confidence.value, finding.title)
```

Targets are normalised the same way the CLI normalises them: a bare host gets
`https://` and trailing slashes are stripped.

Inside an existing async application, await it directly:

```python
async def audit(urls: list[str]) -> webscan.ScanReport:
    return await webscan.scan(urls, plugins=["headers"], concurrency=5)
```

## Blocking callers

`scan_sync()` takes the same keyword arguments and drives its own event loop:

```python
report = webscan.scan_sync(["https://example.com"], plugins=["headers"])
```

It raises `RuntimeError` if called while an event loop is already running —
inside a notebook or an async framework, `await webscan.scan(...)` instead.

## Full parameter reference

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `targets` | `Sequence[str]` | required | Target URLs (positional) |
| `plugins` | `Sequence[str] \| None` | `None` | Plugin names. `None` runs the default set; naming plugins replaces it |
| `concurrency` | `int` | `10` | Targets scanned simultaneously |
| `timeout` | `int` | `10` | Per-request timeout in seconds |
| `soft_404` | `bool` | `False` | Calibrate against a bogus path and suppress soft-404 matches |
| `bruteforce` | `bool` | `True` | DNS brute force in the `subdomains` plugin |
| `retry` | `RetryConfig \| None` | `None` | Retry policy for network-heavy lookups |
| `proxy` | `str` | `""` | HTTP or SOCKS proxy URL |
| `user_agent` | `str` | `""` | User-Agent override |
| `delay` | `float` | `0.0` | Seconds to pause before each target |
| `random_delay` | `bool` | `False` | Jitter `delay` by ×0.5–×1.5 |
| `verify_ssl` | `bool` | `False` | Enforce TLS verification (CLI `--strict-ssl`) |
| `auth_headers` | `dict[str, str] \| None` | `None` | Headers attached to every request |
| `auth_cookies` | `dict[str, str] \| None` | `None` | Cookies attached to every request |
| `on_progress` | `ProgressCallback \| None` | `None` | `(target, done, total) -> None` |
| `min_confidence` | `Confidence \| None` | `None` | Drop findings below this confidence |

All except `targets` are keyword-only.

> `verify_ssl` defaults to `False` because scanners routinely audit hosts with
> self-signed or expired certificates. Set it to `True` for production scans
> where a verification failure is itself a finding.

## Working with the report

The report is plain dataclasses — no custom accessors needed.

```python
from webscan import Severity

report = webscan.scan_sync(["https://example.com"])

print(report.scan_started, report.scan_finished, report.total_findings)

for target in report.targets:
    print(target.target, len(target.findings), "findings")
    for err in target.errors:          # timeouts, DNS failures
        print("  error:", err)

# Critical and high findings across every target
serious = [
    f
    for t in report.targets
    for f in t.findings
    if f.severity in (Severity.CRITICAL, Severity.HIGH)
]
```

Each `Finding` carries `plugin`, `title`, `severity`, `description`, `url`,
`evidence`, `remediation`, `confidence`, and `dedup_key`.

Convert the whole report to plain data with `dataclasses.asdict`:

```python
from dataclasses import asdict

payload = asdict(report)
```

## Rendering reports

`Reporter` produces the same six formats as the CLI. Each method returns a
string and optionally writes to a path:

```python
from pathlib import Path
from webscan import Reporter

reporter = Reporter(report)

json_text = reporter.to_json()
reporter.to_html(Path("report.html"))
reporter.to_sarif(Path("report.sarif"))

for text in (reporter.to_jsonl(), reporter.to_markdown(), reporter.to_csv()):
    ...
```

Risk scoring and compliance mapping are separate helpers:

```python
from webscan.compliance import compliance_summary, map_findings
from webscan.risk import compute_risk_score, risk_grade

score, breakdown = compute_risk_score(report)
print(f"{score:.0f}/100 ({risk_grade(score)})")

mapping = map_findings(report)
for category_id, name, count, status in compliance_summary(mapping):
    print(category_id, name, count, status)
```

## Progress callbacks

```python
def on_progress(target: str, done: int, total: int) -> None:
    print(f"[{done}/{total}] {target}")

report = webscan.scan_sync(["https://a.example", "https://b.example"],
                           on_progress=on_progress)
```

## Inspecting the registry

```python
from webscan import ALL_PLUGINS, DEFAULT_PLUGINS, OPT_IN_PLUGINS

print(len(ALL_PLUGINS))                      # 41
print(len(DEFAULT_PLUGINS))                  # 33
print(sorted(OPT_IN_PLUGINS))                # the 8 opt-in names

for name, cls in ALL_PLUGINS.items():
    print(f"{name:24} {cls.description}")
```

`ALL_PLUGINS` includes any third-party plugin registered under the
`webscan.plugins` entry-point group.

## Error handling

| Exception | Raised when |
|---|---|
| `ValueError` | `targets` is empty, or the plugin list resolves to nothing |
| `KeyError` | An unknown plugin name was requested |
| `RuntimeError` | `scan_sync()` was called inside a running event loop |

Per-target network failures are **not** exceptions — they are collected in
`TargetResult.errors`, so one unreachable host does not abort the scan.

```python
try:
    report = webscan.scan_sync(["https://example.com"], plugins=["nope"])
except KeyError as exc:
    print("unknown plugin:", exc)
```
