"""Tests for the web_cache_deception plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.web_cache_deception import (
    WebCacheDeceptionPlugin,
    _has_sensitive_marker,
    _is_static_content_type,
)

_TARGET = "https://example.com/account/settings"


class _CalibrationSession:
    """Returns 404 for calibration, mapped responses for probes."""

    def __init__(self, baseline: FakeResponse, probes: dict[str, FakeResponse]) -> None:
        self._baseline = baseline
        self._probes = probes

    def get(self, url: str, **_kw: object) -> FakeResponse:
        if "webscan-soft404-probe" in url:
            return FakeResponse(body="", status=404)
        # Original target URL (no extension) returns baseline
        if url == "https://example.com/account/settings":
            return self._baseline
        # Probe URLs return mapped response or 404
        if url in self._probes:
            return self._probes[url]
        return FakeResponse(body="Not Found", status=404)


def _findings_with(f: list, *, t: str) -> list:
    return [x for x in f if t.lower() in x.title.lower()]


class TestHasSensitiveMarker:
    def test_email(self) -> None:
        assert _has_sensitive_marker("<p>email: user@test.com</p>") is True

    def test_api_key(self) -> None:
        assert _has_sensitive_marker("api_key=sk-12345") is True

    def test_session(self) -> None:
        assert _has_sensitive_marker("session_id=abc123") is True

    def test_no_markers(self) -> None:
        assert _has_sensitive_marker("<html><body>Hello world</body></html>") is False


class TestIsStaticContentType:
    def test_css(self) -> None:
        assert _is_static_content_type("text/css") is True

    def test_js(self) -> None:
        assert _is_static_content_type("application/javascript") is True

    def test_png(self) -> None:
        assert _is_static_content_type("image/png") is True

    def test_html_not_static(self) -> None:
        assert _is_static_content_type("text/html") is False

    def test_empty(self) -> None:
        assert _is_static_content_type("") is False


class TestPluginRun:
    async def test_high_when_sensitive_data_at_extension(self) -> None:
        plugin = WebCacheDeceptionPlugin()
        baseline_body = (
            "<html><body><h1>Account Settings</h1>"
            "<p>email: alice@example.com</p>"
            "<p>api_key: sk-test123</p>"
            "<p>Additional content for body length padding to exceed the minimum threshold requirement properly.</p>"  # noqa: E501
            "</body></html>"
        )
        baseline = FakeResponse(body=baseline_body, status=200, headers=[("Content-Type", "text/html")])  # noqa: E501
        # Probe: same body but at .css URL, still text/html
        probe_resp = FakeResponse(body=baseline_body, status=200, headers=[("Content-Type", "text/html")])  # noqa: E501
        session = _CalibrationSession(baseline, {"https://example.com/account/settings.css": probe_resp})  # noqa: E501
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        high = _findings_with(findings, t="sensitive data")
        assert len(high) == 1
        assert high[0].severity is Severity.HIGH
        assert high[0].confidence is Confidence.FIRM

    async def test_medium_when_dynamic_page_no_sensitive(self) -> None:
        plugin = WebCacheDeceptionPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with content.</p>"
            "<p>Additional content for body length padding to exceed the minimum threshold requirement properly.</p>"  # noqa: E501
            "</body></html>"
        )
        baseline = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        probe_resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        session = _CalibrationSession(baseline, {"https://example.com/account/settings.css": probe_resp})  # noqa: E501
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        medium = _findings_with(findings, t="dynamic page")
        assert len(medium) == 1
        assert medium[0].severity is Severity.MEDIUM
        assert medium[0].confidence is Confidence.TENTATIVE

    async def test_no_finding_when_static_content_type(self) -> None:
        """If .css returns text/css, that's correct caching — no finding."""
        plugin = WebCacheDeceptionPlugin()
        baseline = FakeResponse(
            body="<html><body>Settings</body></html>" + "x" * 200,
            status=200, headers=[("Content-Type", "text/html")],
        )
        # Map ALL extensions to their correct static content types
        static_probes = {}
        for ext in [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico",
                     ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".pdf", ".xml", ".txt"]:
            url = f"https://example.com/account/settings{ext}"
            if ext == ".css":
                ct = "text/css"
            elif ext == ".js":
                ct = "application/javascript"
            elif ext in (".png", ".jpg", ".gif", ".svg", ".ico"):
                ct = f"image/{ext[1:]}"
            elif ext in (".woff", ".woff2", ".ttf"):
                ct = f"font/{ext[1:]}"
            elif ext == ".mp4":
                ct = "video/mp4"
            elif ext == ".mp3":
                ct = "audio/mpeg"
            elif ext == ".pdf":
                ct = "application/pdf"
            elif ext == ".xml":
                ct = "application/xml"
            else:
                ct = "text/plain"
            static_probes[url] = FakeResponse(body="x" * 200, status=200, headers=[("Content-Type", ct)])  # noqa: E501
        session = _CalibrationSession(baseline, static_probes)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_404(self) -> None:
        plugin = WebCacheDeceptionPlugin()
        baseline = FakeResponse(body="<html><body>Settings</body></html>" + "x" * 200, status=200, headers=[("Content-Type", "text/html")])  # noqa: E501
        session = _CalibrationSession(baseline, {})
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_non_html_baseline_skipped(self) -> None:
        plugin = WebCacheDeceptionPlugin()
        resp = FakeResponse(body='{"data":1}', status=200, headers=[("Content-Type", "application/json")])  # noqa: E501
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_short_body_skipped(self) -> None:
        plugin = WebCacheDeceptionPlugin()
        resp = FakeResponse(body="<html>ok</html>", status=200, headers=[("Content-Type", "text/html")])  # noqa: E501
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_network_error_returns_empty(self) -> None:
        plugin = WebCacheDeceptionPlugin()

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

    async def test_evidence_includes_extension_and_url(self) -> None:
        plugin = WebCacheDeceptionPlugin()
        body = "<html><body>email: a@b.com</body></html>" + "x" * 200
        baseline = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        probe_resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        session = _CalibrationSession(baseline, {"https://example.com/account/settings.css": probe_resp})  # noqa: E501
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        high = _findings_with(findings, t="sensitive data")[0]
        ev = high.evidence
        assert ev["extension"] == ".css"
        assert "probe_url" in ev
        assert ev["has_sensitive_markers"] is True
