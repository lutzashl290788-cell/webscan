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


class TestCoverageGaps:
    """Tests targeting uncovered lines to boost coverage."""

    async def test_js_fetch_network_error(self) -> None:
        """Line 100: except branch when fetching JS fails."""
        plugin = PrototypePollutionPlugin()
        body = (
            '<html><head>'
            '<script src="https://example.com/broken.js"></script>'
            '</head><body>Content here for length.</body></html>'
        )

        class _BoomJsSession:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                if "broken.js" in url:
                    return _BoomResp()
                return FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])

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
            findings = await plugin.run(_TARGET, _BoomJsSession())  # type: ignore[arg-type]
            assert isinstance(findings, list)
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_merge_function_definition_detected(self) -> None:
        """Lines 142-167: LOW finding for merge/extend function definition."""
        plugin = PrototypePollutionPlugin()
        body = (
            '<html><body><script>'
            'function extend() { return {}; }'
            '</script>' + "x" * 100 + '</body></html>'
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        low = _findings_with(findings, title_contains="Merge/extend")
        assert len(low) == 1
        assert low[0].severity is Severity.LOW

    async def test_const_merge_definition(self) -> None:
        """Line 143: const merge = pattern."""
        plugin = PrototypePollutionPlugin()
        body = (
            '<html><body><script>'
            'const extend = (a) => a;'
            '</script>' + "x" * 100 + '</body></html>'
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        low = _findings_with(findings, title_contains="Merge/extend")
        assert len(low) >= 1
