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


class TestMoreCoverageGaps:
    async def test_main_page_network_error_returns_empty(self) -> None:
        """Lines 79-80: a ClientError fetching the main page yields no findings."""
        import aiohttp

        class _ClientError(Exception):
            pass

        class _RaisingResp:
            async def __aenter__(self) -> _RaisingResp:
                raise _ClientError("down")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

            async def text(self, **_kw: object) -> str:
                return ""

        class _BoomSession:
            def get(self, _url: str, **_kw: object) -> _RaisingResp:
                return _RaisingResp()

        orig = aiohttp.ClientError
        aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
        try:
            plugin = PrototypePollutionPlugin()
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_external_js_with_vulnerable_pattern_loaded(self) -> None:
        """Lines 97-99: a same-origin JS file is fetched and scanned successfully."""
        plugin = PrototypePollutionPlugin()
        html_body = (
            '<html><head>'
            '<script src="https://example.com/app.js"></script>'
            '</head><body>Content here for length padding.</body></html>'
        )
        js_body = '$.extend(true, {}, userInput);'  # vulnerable pattern

        class _JsSession:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                if url == "https://example.com/app.js":
                    return FakeResponse(body=js_body, status=200)
                return FakeResponse(
                    body=html_body, status=200, headers=[("Content-Type", "text/html")],
                )

        findings = await plugin.run(_TARGET, _JsSession())  # type: ignore[arg-type]
        medium = _findings_with(findings, title_contains="Prototype pollution")
        assert len(medium) >= 1

    async def test_non_html_url_with_html_extension_scanned(self) -> None:
        """Line 76-77: a non-HTML content-type but .html URL is still scanned."""
        plugin = PrototypePollutionPlugin()
        body = (
            '<html><script>$.extend(true, {}, userInput);</script></html>'
            + " " * 50
        )
        # Content-Type is JSON, but the URL ends in .html → still scanned.
        resp = FakeResponse(
            body=body, status=200, headers=[("Content-Type", "application/json")],
        )
        findings = await plugin.run("https://example.com/page.html", FakeSession(resp))  # type: ignore[arg-type]
        medium = _findings_with(findings, title_contains="Prototype pollution")
        assert len(medium) >= 1
