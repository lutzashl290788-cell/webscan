"""Tests for the websocket_security plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.websocket_security import (
    WebsocketSecurityPlugin,
    _find_ws_urls,
    _has_sensitive_context,
)

_TARGET = "https://example.com/"


def _findings_with(f: list, *, t: str) -> list:
    return [x for x in f if t.lower() in x.title.lower()]


class TestFindWsUrls:
    def test_finds_ws_url(self) -> None:
        text = 'var ws = new WebSocket("ws://example.com/chat");'
        results = _find_ws_urls(text)
        assert len(results) == 1
        assert results[0][0] == "ws://example.com/chat"

    def test_finds_wss_url(self) -> None:
        text = 'connect("wss://api.example.com/ws")'
        results = _find_ws_urls(text)
        assert len(results) == 1
        assert results[0][0] == "wss://api.example.com/ws"

    def test_finds_multiple(self) -> None:
        text = (
            'var a = "ws://chat.example.com";'
            'var b = "wss://api.example.com/ws";'
        )
        results = _find_ws_urls(text)
        assert len(results) == 2

    def test_no_ws_urls(self) -> None:
        text = "<html><body>No websockets here</body></html>"
        assert _find_ws_urls(text) == []

    def test_context_captured(self) -> None:
        text = (
            "const token = getUserToken();"
            'var ws = new WebSocket("wss://api.example.com/ws");'
        )
        results = _find_ws_urls(text)
        assert len(results) == 1
        assert "token" in results[0][2]


class TestHasSensitiveContext:
    def test_token(self) -> None:
        assert _has_sensitive_context("var token = abc;") is True

    def test_auth(self) -> None:
        assert _has_sensitive_context("authorization: Bearer ...") is True

    def test_session(self) -> None:
        assert _has_sensitive_context("session_id = 123") is True

    def test_no_keywords(self) -> None:
        assert _has_sensitive_context("var x = 42;") is False


class TestPluginRun:
    async def test_high_for_unencrypted_ws(self) -> None:
        plugin = WebsocketSecurityPlugin()
        body = (
            '<html><body><h1>Chat</h1>'
            '<script>var ws = new WebSocket("ws://chat.example.com/ws");</script>'
            + "x" * 50 +
            "</body></html>"
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        high = _findings_with(findings, t="Insecure WebSocket")
        assert len(high) == 1
        assert high[0].severity is Severity.HIGH
        assert high[0].confidence is Confidence.FIRM

    async def test_medium_for_wss_with_sensitive_context(self) -> None:
        plugin = WebsocketSecurityPlugin()
        body = (
            '<html><body><h1>Dashboard</h1>'
            '<script>'
            'const token = getToken();'
            'var ws = new WebSocket("wss://api.example.com/ws");'
            '</script>'
            + "x" * 50 +
            "</body></html>"
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        med = _findings_with(findings, t="sensitive context")
        assert len(med) == 1
        assert med[0].severity is Severity.MEDIUM
        assert med[0].confidence is Confidence.TENTATIVE

    async def test_low_for_wss_no_sensitive(self) -> None:
        plugin = WebsocketSecurityPlugin()
        body = (
            '<html><body><h1>Live Scores</h1>'
            '<script>var ws = new WebSocket("wss://scores.example.com/live");</script>'
            + "x" * 50 +
            "</body></html>"
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        low = _findings_with(findings, t="discovered")
        assert len(low) == 1
        assert low[0].severity is Severity.LOW
        assert low[0].confidence is Confidence.INFORMATIONAL

    async def test_no_finding_when_no_ws_urls(self) -> None:
        plugin = WebsocketSecurityPlugin()
        body = "<html><body>No websockets here</body></html>" + "x" * 50
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_non_html_skipped(self) -> None:
        plugin = WebsocketSecurityPlugin()
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])  # noqa: E501
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_dedupe_same_url(self) -> None:
        plugin = WebsocketSecurityPlugin()
        body = (
            '<html><body>'
            '<script>var a = "ws://chat.example.com/ws";</script>'
            '<script>var b = "ws://chat.example.com/ws";</script>'
            + "x" * 50 +
            "</body></html>"
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        # Same URL deduped — only 1 finding.
        assert len(findings) == 1

    async def test_network_error_returns_empty(self) -> None:
        plugin = WebsocketSecurityPlugin()

        class _BoomSession:
            def get(self, url: str, **_kw: object) -> _BoomResp:
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
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_evidence_includes_ws_url_and_scheme(self) -> None:
        plugin = WebsocketSecurityPlugin()
        body = (
            '<html><body><script>'
            'var ws = new WebSocket("ws://chat.example.com/ws");'
            '</script>' + "x" * 50 + "</body></html>"
        )
        resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        high = _findings_with(findings, t="Insecure WebSocket")[0]
        ev = high.evidence
        assert ev["ws_url"] == "ws://chat.example.com/ws"
        assert ev["scheme"] == "ws"
        assert "location" in ev
