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


# ----------------------------------------------------------------------
# Boolean-based blind
# ----------------------------------------------------------------------

class _BoolResponse:
    def __init__(self, body: str) -> None:
        self._body = body

    async def __aenter__(self) -> _BoolResponse:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self) -> str:
        return self._body


class _BoolSession:
    """Returns a 'logged in' body for TRUE conditions, 'denied' for FALSE."""

    def __init__(self) -> None:
        self.calls = 0

    def get(self, url: str, **_kw: object) -> _BoolResponse:
        self.calls += 1
        # FALSE conditions contain 1=2 or '1'='2'
        if "1%3D2" in url or "1%27%3D%272" in url or "1'='2" in url or "1=2" in url:
            return _BoolResponse("<html>Access denied</html>")
        return _BoolResponse("<html>Welcome back, admin! Dashboard loaded.</html>")


async def test_detects_boolean_blind() -> None:
    plugin = SqlInjectionPlugin()
    session = _BoolSession()

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].evidence["type"] == "boolean-blind"
    assert findings[0].severity is Severity.CRITICAL


# ----------------------------------------------------------------------
# Time-based blind
# ----------------------------------------------------------------------

class _TimeResponse:
    def __init__(self, delay: float) -> None:
        self._delay = delay

    async def __aenter__(self) -> _TimeResponse:
        import asyncio
        if self._delay:
            await asyncio.sleep(self._delay)
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self) -> str:
        return "<html>same body always</html>"


class _TimeSession:
    """Sleeps when a time-based payload keyword is present in the URL."""

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self.calls = 0

    def get(self, url: str, **_kw: object) -> _TimeResponse:
        self.calls += 1
        lowered = url.lower()
        if any(k in lowered for k in ("sleep", "pg_sleep", "waitfor", "dbms_lock")):
            return _TimeResponse(self._delay)
        return _TimeResponse(0.0)


async def test_detects_time_blind(monkeypatch: object) -> None:
    import webscan.plugins.sql_injection as sqli

    # Shrink the delay so the test runs fast while keeping the logic intact.
    monkeypatch.setattr(sqli, "_DELAY_SECONDS", 1)

    plugin = sqli.SqlInjectionPlugin()
    session = _TimeSession(delay=1.0)

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].evidence["type"] == "time-blind"


async def test_fast_site_no_time_false_positive() -> None:
    plugin = SqlInjectionPlugin()
    session = _TimeSession(delay=0.0)  # never sleeps

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert findings == []
