"""Tests for the request_smuggling plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.request_smuggling import RequestSmugglingPlugin

_TARGET = "https://example.com/"

def _findings_with(findings: list, *, title_contains: str) -> list:
    return [x for x in findings if title_contains.lower() in x.title.lower()]

class TestPluginRun:
    async def test_non_smuggling_response_no_finding(self) -> None:
        plugin = RequestSmugglingPlugin()
        resp = FakeResponse(body="<html>Normal response</html>", status=200)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_cl_te_detected_when_marker_in_followup(self) -> None:
        plugin = RequestSmugglingPlugin()
        class _Session:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="webscan-smuggling-probe found", status=200)
            def post(self, url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="ok", status=200)
        findings = await plugin.run(_TARGET, _Session())  # type: ignore[arg-type]
        smuggling = _findings_with(findings, title_contains="smuggling")
        assert len(smuggling) == 1
        assert smuggling[0].severity is Severity.CRITICAL


class TestCoverageGaps:
    """Tests targeting uncovered lines."""

    async def test_te_cl_timeout_detected(self) -> None:
        """Lines 127-154: TE.CL timeout finding."""
        plugin = RequestSmugglingPlugin()

        class _TimeoutSession:
            def get(self, url: str, **_kw: object) -> _TimeoutResp:
                return _TimeoutResp()
            def post(self, url: str, **_kw: object) -> _TimeoutResp:
                return _TimeoutResp()

        class _TimeoutResp:
            async def __aenter__(self) -> _TimeoutResp:
                import asyncio
                raise asyncio.TimeoutError()
            async def __aexit__(self, *_exc: object) -> bool:
                return False

        findings = await plugin.run(_TARGET, _TimeoutSession())  # type: ignore[arg-type]
        te_cl = _findings_with(findings, title_contains="TE.CL")
        assert len(te_cl) == 1
        assert te_cl[0].severity is Severity.CRITICAL

    async def test_post_network_error(self) -> None:
        """Line 155: except (ClientError, UnicodeError) branch."""
        plugin = RequestSmugglingPlugin()

        class _BoomPostSession:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="<html>ok</html>", status=200)
            def post(self, url: str, **_kw: object) -> _BoomResp:
                return _BoomResp()

        class _BoomResp:
            async def __aenter__(self) -> _BoomResp:
                raise _ClientError("boom")
            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _ClientError(Exception):
            pass

        import aiohttp
        orig = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            findings = await plugin.run(_TARGET, _BoomPostSession())  # type: ignore[arg-type]
            assert isinstance(findings, list)
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]
