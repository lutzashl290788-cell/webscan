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
