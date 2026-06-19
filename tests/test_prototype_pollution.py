"""Tests for the prototype_pollution plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.prototype_pollution import PrototypePollutionPlugin

_TARGET = "https://example.com/"

def _findings_with(findings: list, *, title_contains: str) -> list:
    return [x for x in findings if title_contains.lower() in x.title.lower()]

class TestPluginRun:
    async def test_jquery_extend_detected(self) -> None:
        plugin = PrototypePollutionPlugin()
        body = '<html><script>$.extend(true, {}, userInput);</script></html>' + " " * 50
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        medium = _findings_with(findings, title_contains="Prototype pollution")
        assert len(medium) >= 1
        assert medium[0].severity is Severity.MEDIUM

    async def test_no_patterns_no_finding(self) -> None:
        plugin = PrototypePollutionPlugin()
        body = '<html><body>Hello world</body></html>' + " " * 50
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_non_html_skipped(self) -> None:
        plugin = PrototypePollutionPlugin()
        resp = FakeResponse(body='{"x":1}', status=200, headers=[("Content-Type",
            "application/json")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []
