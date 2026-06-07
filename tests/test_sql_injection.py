"""Tests for the sql_injection plugin.

A lightweight fake session is used instead of a real HTTP mock: the plugin
only needs ``session.get(url, ...)`` as an async context manager whose
response exposes ``await .text()``.
"""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.sql_injection import SqlInjectionPlugin


class _FakeResponse:
    def __init__(self, body: str) -> None:
        self._body = body

    async def __aenter__(self) -> _FakeResponse:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self) -> str:
        return self._body


class _FakeSession:
    """Returns the same canned body for every request and records call count."""

    def __init__(self, body: str) -> None:
        self._body = body
        self.calls = 0

    def get(self, _url: str, **_kwargs: object) -> _FakeResponse:
        self.calls += 1
        return _FakeResponse(self._body)


async def test_detects_database_error() -> None:
    plugin = SqlInjectionPlugin()
    session = _FakeSession("You have an error in your SQL syntax; check the manual")

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin == "sql_injection"
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["parameter"] == "id"


async def test_no_query_params_skips_scan() -> None:
    plugin = SqlInjectionPlugin()
    session = _FakeSession("irrelevant")

    findings = await plugin.run("https://example.com/", session)  # type: ignore[arg-type]

    assert findings == []
    assert session.calls == 0  # no request made when there is nothing to fuzz


async def test_clean_response_yields_no_findings() -> None:
    plugin = SqlInjectionPlugin()
    session = _FakeSession("<html>all good</html>")

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert findings == []
