# Contributing to WebScan

Thank you for taking the time to contribute! This document covers everything you need to go from zero to a working dev environment, run the test suite, and write your first plugin.

---

## Table of Contents

1. [Development setup](#1-development-setup)
2. [Running tests](#2-running-tests)
3. [Linting and type-checking](#3-linting-and-type-checking)
4. [Writing a plugin](#4-writing-a-plugin)
5. [Submitting changes](#5-submitting-changes)
6. [Further reading](#6-further-reading)

---

## 1. Development setup

**Prerequisites:** Python 3.11 or later, and `git`.

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/<your-handle>/webscan.git
cd webscan

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install in editable mode with all dev dependencies
pip install -e ".[dev]"

# 4. Verify the CLI works
webscan --list-plugins
```

The `[dev]` extra installs `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`, and `types-PyYAML` — everything needed for tests, lint, and type checks.

Optionally install the git hooks so the same checks run before each commit:

```bash
pip install pre-commit
pre-commit install
```

---

## 2. Running tests

```bash
# Run the full test suite
pytest

# Run a single test file
pytest tests/test_cookies.py

# Run tests matching a name pattern
pytest -k "sql_injection"

# Show verbose output
pytest -v
```

Tests live in `tests/` and use the `FakeSession` / `FakeResponse` helpers in `tests/_fakes.py` to avoid real HTTP calls. All tests are async; `asyncio_mode = "auto"` is set in `pyproject.toml` so no `@pytest.mark.asyncio` decorator is needed.

---

## 3. Linting and type-checking

```bash
# Lint and auto-fix with Ruff
ruff check --fix .

# Format with Ruff
ruff format .

# Run strict mypy type checks
mypy webscan
```

Both tools are configured in `pyproject.toml`. A PR must pass both before it can be merged.

CI additionally enforces a **coverage floor of 80%**:

```bash
pytest -q --cov=webscan --cov-report=term-missing --cov-fail-under=80
```

---

## 4. Writing a plugin

The short version is in the README; here is the complete checklist:

### Step 1 — Create the module

Add `webscan/plugins/my_plugin.py`:

```python
"""Plugin: describe what it checks in one line."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
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
                # ... perform checks on resp ...
                pass
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings  # never raise — return partial results

        return findings
```

**Rules:**
- `name` must be unique, lowercase, and use underscores (it becomes the `--plugins` flag value).
- `run` must never raise — catch `aiohttp.ClientError` and `asyncio.TimeoutError` at minimum.
- Each finding should carry a `remediation` string so users know how to fix the issue.

### Step 2 — Register it

Registration happens in two places, both required.

**1. The registry** — `webscan/registry.py` is the single source of truth for
plugin identity, shared by the CLI and the library API:

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

If your plugin sends heavy, external, or state-changing requests, also add its
name to `OPT_IN_PLUGINS` in the registry so it stays out of the default run,
with a comment explaining why.

### Step 3 — Add tests

Create `tests/test_my_plugin.py`. Use `FakeSession` / `FakeResponse` from `tests/_fakes.py` so tests run without network access:

```python
from tests._fakes import FakeResponse, FakeSession
from webscan.plugins.my_plugin import MyPlugin

_TARGET = "https://example.com"


async def test_finding_is_reported() -> None:
    plugin = MyPlugin()
    resp = FakeResponse(...)  # set up headers / status as needed
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].severity == ...


async def test_no_finding_when_safe() -> None:
    plugin = MyPlugin()
    resp = FakeResponse(...)
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
    assert findings == []
```

### Step 4 — Verify everything passes

```bash
pytest
ruff check --fix .
mypy webscan
```

---

## 5. Submitting changes

1. Branch off `main`: `git checkout -b feat/my-plugin`
2. Commit with a clear message: `feat: add my_plugin — checks X`
3. Open a pull request and fill in the PR template.
4. All CI checks (tests, ruff, mypy) must be green before review.

For significant changes, open a feature-request issue first to align on design before writing code.

---

## 6. Further reading

- [docs/plugin-development.md](docs/plugin-development.md) — the full plugin contract, active-scan helpers, and how to publish a third-party plugin
- [docs/architecture.md](docs/architecture.md) — module map, scan pipeline, and the design constraints behind them
- [SECURITY.md](SECURITY.md) — reporting a vulnerability in WebScan itself
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards
