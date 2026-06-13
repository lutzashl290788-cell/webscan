"""Tests for the exposed-config-files plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.config_files import ConfigFilesPlugin

_BASE = "https://example.com"


class _Resp:
    def __init__(self, status: int) -> None:
        self.status = status
        self.headers: dict[str, str] = {}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _Session:
    """Returns 200 for a configured set of paths, 404 otherwise."""

    def __init__(self, present: set[str]) -> None:
        self._present = present

    def get(self, url: str, **_kw: object) -> _Resp:
        path = url[len(_BASE):]
        return _Resp(200 if path in self._present else 404)


async def test_flags_exposed_env_as_critical() -> None:
    session = _Session({"/.env"})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].title == "Exposed file: /.env"
    assert findings[0].severity is Severity.CRITICAL


async def test_severity_classification() -> None:
    session = _Session({"/.git/config", "/package.json"})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    by_path = {f.title: f.severity for f in findings}

    assert by_path["Exposed file: /.git/config"] is Severity.HIGH
    assert by_path["Exposed file: /package.json"] is Severity.MEDIUM


async def test_clean_target_no_findings() -> None:
    session = _Session(set())
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []
