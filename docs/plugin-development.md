# Plugin development

A WebScan plugin is a class with a name, a description, and one async `run()`
method. This guide covers the contract, the helpers, testing, and how to ship a
plugin inside the package or as a separate distribution.

## Contents

- [The contract](#the-contract)
- [A minimal plugin](#a-minimal-plugin)
- [Registering a built-in plugin](#registering-a-built-in-plugin)
- [Shipping a third-party plugin](#shipping-a-third-party-plugin)
- [Writing good findings](#writing-good-findings)
- [Active-scan helpers](#active-scan-helpers)
- [Testing](#testing)
- [Checklist](#checklist)

## The contract

Every plugin subclasses `BasePlugin`:

```python
class BasePlugin(ABC):
    name: str = ""          # machine-readable id, used by --plugins
    description: str = ""   # one line, shown by --list-plugins

    @abstractmethod
    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]: ...
```

Four rules the engine relies on:

1. **`run()` must never raise.** Catch `aiohttp.ClientError` and
   `asyncio.TimeoutError` at minimum, and return the findings collected so far.
   An exception escaping a plugin degrades the whole target's result.
2. **`name` is unique, lowercase, underscore-separated.** It becomes the
   `--plugins` value.
3. **Use the session you are given.** It carries the operator's proxy, auth,
   User-Agent, rate limiting, and TLS settings. Creating your own session
   silently bypasses `--safe-mode`, `--proxy`, and every auth flag.
4. **Every finding carries a `remediation`.** A finding a user cannot act on is
   noise.

## A minimal plugin

`webscan/plugins/my_plugin.py`:

```python
"""Plugin: describe what it checks in one line."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin


class MyPlugin(BasePlugin):
    name = "my_plugin"
    description = "One-line description shown by --list-plugins"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, ssl=False) as resp:
                header = resp.headers.get("X-Example-Protection", "")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings          # never raise — return partial results

        if not header:
            findings.append(Finding(
                plugin=self.name,
                title="Missing X-Example-Protection header",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                description=(
                    "The response does not set X-Example-Protection, so "
                    "browsers fall back to permissive behaviour."
                ),
                url=target,
                evidence={"header": "X-Example-Protection", "observed": None},
                remediation="Set 'X-Example-Protection: 1' on all responses.",
            ))

        return findings
```

The `ssl=False` argument keeps the scanner able to audit hosts with self-signed
or expired certificates, which is the CLI default and what most existing
plugins pass.

> **Note:** a per-request `ssl=` argument takes precedence over the SSL context
> the engine configures on its connector, so a plugin that hard-codes
> `ssl=False` does not follow `--strict-ssl`. Omit the argument if you want your
> plugin to honour the operator's TLS setting.

## Registering a built-in plugin

Two places, both required:

**1. The registry** — `webscan/registry.py`:

```python
from webscan.plugins.my_plugin import MyPlugin

_BUILTIN_PLUGINS: dict[str, type[BasePlugin]] = {
    ...,
    "my_plugin": MyPlugin,
}
```

**2. The entry point** — `pyproject.toml`:

```toml
[project.entry-points."webscan.plugins"]
my_plugin = "webscan.plugins.my_plugin:MyPlugin"
```

If the plugin sends heavy, external, or state-changing requests, also add it to
`OPT_IN_PLUGINS` in the registry so it stays out of the default run — and say
why in a comment next to it.

## Shipping a third-party plugin

A plugin does not have to live in this repository. Publish a package that
declares the entry point:

```toml
# your-package/pyproject.toml
[project]
name = "webscan-myplugin"
dependencies = ["webscan-security>=2.8"]

[project.entry-points."webscan.plugins"]
my_plugin = "webscan_myplugin.plugin:MyPlugin"
```

Install it alongside WebScan and it appears in `--list-plugins` automatically.

Two guarantees to know about:

- **Built-ins cannot be shadowed.** An entry point whose name collides with a
  built-in is reported on stderr and skipped, so a package cannot silently
  replace `headers` and harvest your credentials.
- **Discovery is fail-safe.** A plugin that fails to import is skipped, not
  fatal — one broken package cannot stop a scan.

## Writing good findings

| Field | Guidance |
|---|---|
| `title` | The problem, not the check. "Missing HSTS header", not "HSTS check". |
| `severity` | Impact if real. Reserve `critical` for direct compromise. |
| `confidence` | `FIRM` only when directly observed or content-verified. Heuristics are `TENTATIVE`. |
| `description` | What was observed and why it matters, in plain language. |
| `url` | The exact URL the finding applies to, not the seed target. |
| `evidence` | The data that proves it — headers, matched string, status codes. Keep it small. |
| `remediation` | Concrete and copy-pasteable where possible. |
| `dedup_key` | Set when another plugin can detect the same issue. Prefix with `site:` for host-wide issues. |

**Verify before reporting.** The project's whole premise is signal over noise:
confirm a payload was reflected unescaped, that a file's content matches what
its name claims, that a 200 is not a soft 404. If you cannot verify, downgrade
`confidence` rather than raise a firm finding.

## Active-scan helpers

`webscan/plugins/_active_helpers.py` holds the shared machinery for
path-probing and payload-based plugins:

| Helper | Purpose |
|---|---|
| `fetch_body(resp, limit=...)` | Read a response body with a size cap |
| `fetch_with_retry(...)` | GET with the operator's retry/backoff policy |
| `fetch_with_headers(...)` | GET returning body and headers together |
| `calibrate_target(...)` | Request a known-bogus path to learn the site's 404 behaviour |
| `is_soft404(...)` | Test a response against that calibration |
| `body_similarity(a, b)` | Ratio used to tell a real hit from a generic page |
| `looks_like_xml_or_json(...)` | Content-type and body sniffing |

Use `calibrate_target` + `is_soft404` in any plugin that probes for paths.
Sites that answer `200` for everything are the single largest source of false
positives.

## Testing

Tests use the fakes in `tests/_fakes.py`, so the suite runs with no network
access. `asyncio_mode = "auto"` is set in `pyproject.toml`, so async tests need
no decorator.

`tests/test_my_plugin.py`:

```python
from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.my_plugin import MyPlugin

_TARGET = "https://example.com"


async def test_reports_when_header_missing() -> None:
    resp = FakeResponse(status=200, headers=[("Content-Type", "text/html")])
    findings = await MyPlugin().run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].remediation


async def test_silent_when_header_present() -> None:
    resp = FakeResponse(status=200, headers=[("X-Example-Protection", "1")])
    findings = await MyPlugin().run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert findings == []
```

Always cover both directions. A plugin that only has a positive test will
happily report on every site in the world.

`FakeSession` also records what was requested, which is how you assert a plugin
stays polite:

```python
session = FakeSession(FakeResponse(status=404))
await MyPlugin().run(_TARGET, session)  # type: ignore[arg-type]
assert len(session.requests) <= 3
```

## Checklist

Before opening a pull request:

```bash
pytest
ruff check --fix .
mypy webscan
```

- [ ] `run()` cannot raise
- [ ] Both the finding and no-finding paths are tested
- [ ] Every finding has a `remediation`
- [ ] `confidence` honestly reflects verification strength
- [ ] `dedup_key` set if another plugin detects the same issue
- [ ] Registered in `_BUILTIN_PLUGINS` **and** `pyproject.toml`
- [ ] Added to `OPT_IN_PLUGINS` if heavy, external, or state-changing
- [ ] Listed in the [plugin reference](plugins.md) and `README.md`

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the wider contribution process.
