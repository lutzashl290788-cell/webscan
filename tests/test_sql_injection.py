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


class _ErrorSession:
    """Models real error-based SQLi: a DB error surfaces only when a quote/SQL
    payload is injected; the untouched baseline value returns a clean page."""

    _ERROR = "You have an error in your SQL syntax; check the manual"

    def __init__(self) -> None:
        self.calls = 0

    def get(self, url: str, **_kw: object) -> _FakeResponse:
        self.calls += 1
        # Injected payloads contain a URL-encoded quote (%27) or comment marker.
        if "%27" in url or "%22" in url or "ORDER+BY" in url or "--" in url:
            return _FakeResponse(self._ERROR)
        return _FakeResponse("<html>all good</html>")


async def test_detects_database_error() -> None:
    plugin = SqlInjectionPlugin()
    session = _ErrorSession()

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin == "sql_injection"
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["parameter"] == "id"


async def test_db_error_already_in_baseline_is_not_flagged() -> None:
    """A page that always contains a DB-error string (docs, WAF page) is not SQLi."""
    plugin = SqlInjectionPlugin()
    session = _FakeSession("You have an error in your SQL syntax; see our FAQ")

    findings = await plugin.run("https://example.com/?id=1", session)  # type: ignore[arg-type]

    assert findings == []


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


# ----------------------------------------------------------------------
# Coverage gaps — error / transient-failure branches
# ----------------------------------------------------------------------

import aiohttp  # noqa: E402

from webscan.plugins import sql_injection as sqli_mod  # noqa: E402


class _ClientError(Exception):
    pass


class _RaisingResp:
    """A response context manager that raises on __aenter__ (transport error)."""

    async def __aenter__(self) -> _RaisingResp:
        raise _ClientError("network down")

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return ""


class _AlwaysFailingSession:
    """Every GET raises — exercises the except branches in the plugin."""

    def __init__(self) -> None:
        self.calls = 0

    def get(self, _url: str, **_kw: object) -> _RaisingResp:
        self.calls += 1
        return _RaisingResp()


def _patch_client_error() -> object:
    """Swap aiohttp.ClientError for the local test double, return a restorer."""
    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    return orig


def _restore_client_error(orig: object) -> None:
    aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_error_based_baseline_network_error_skipped() -> None:
    """Line 133: a network error on the baseline GET yields no finding."""
    orig = _patch_client_error()
    try:
        plugin = SqlInjectionPlugin()
        session = _AlwaysFailingSession()
        findings = await plugin.run(
            "https://example.com/?id=1", session  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        _restore_client_error(orig)


async def test_get_text_network_error_returns_none() -> None:
    """Lines 299-300: ``_get_text`` swallows a ClientError and returns None."""
    orig = _patch_client_error()
    try:
        plugin = SqlInjectionPlugin()
        session = _AlwaysFailingSession()
        out = await plugin._get_text(session, "https://example.com/?id=1")  # type: ignore[arg-type]
        assert out is None
    finally:
        _restore_client_error(orig)


async def test_timed_get_network_error_returns_none() -> None:
    """Lines 310-311: ``_timed_get`` swallows a ClientError and returns None."""
    orig = _patch_client_error()
    try:
        plugin = SqlInjectionPlugin()
        session = _AlwaysFailingSession()
        out = await plugin._timed_get(session, "https://example.com/?id=1")  # type: ignore[arg-type]
        assert out is None
    finally:
        _restore_client_error(orig)


class _NoneResp:
    """Response whose __aenter__ raises, simulating a one-off network failure."""

    async def __aenter__(self) -> _NoneResp:
        raise _ClientError("flaky")

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return ""


class _FlakyBoolSession:
    """Returns a normal body for the first baseline, then raises for the second.

    Drives the boolean-blind ``base2 is None`` early-out (line 179) and the
    ``true_body is None or false_body is None`` continue (line 194).
    """

    def __init__(self) -> None:
        self.calls = 0

    def get(self, _url: str, **_kw: object) -> object:
        self.calls += 1
        # Call 1 & 2 are the stability baseline. Make call 2 raise → base2 None.
        if self.calls == 2:
            return _NoneResp()
        # Later calls (the TRUE/FALSE legs) also raise → exercises the continue.
        if self.calls >= 5:
            return _NoneResp()
        return _FakeResponse("<html>stable page content here</html>")


async def test_boolean_blind_baseline_failure_skipped() -> None:
    """Lines 179/181: if one stability-baseline fetch fails, boolean is skipped."""
    orig = _patch_client_error()
    try:
        plugin = SqlInjectionPlugin()
        session = _FlakyBoolSession()
        findings = await plugin.run(
            "https://example.com/?id=1", session  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        _restore_client_error(orig)


class _SlowBaselineTimeSession:
    """Time-blind: baseline is already slower than the delay threshold (line 251).

    Every probe sleeps just above the (shrunken) delay threshold so the plugin
    bails out of the time-blind check before sending a payload. The delay is
    tiny (kept just over the threshold) so the full test stays fast even though
    the error-based and boolean checks also issue requests through this session.
    """

    def __init__(self) -> None:
        self.calls = 0

    def get(self, url: str, **_kw: object) -> _TimeResponse:
        self.calls += 1
        # Just over the threshold set in the test via monkeypatch.
        return _TimeResponse(0.06)


async def test_time_blind_slow_baseline_skipped(monkeypatch: object) -> None:
    """Lines 248/251: a site already slower than the delay yields no finding."""
    monkeypatch.setattr(sqli_mod, "_DELAY_SECONDS", 0.05)
    plugin = sqli_mod.SqlInjectionPlugin()
    session = _SlowBaselineTimeSession()
    findings = await plugin.run(
        "https://example.com/?id=1", session  # type: ignore[arg-type]
    )
    assert findings == []
