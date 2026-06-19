"""Tests for the verbose_errors plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.verbose_errors import VerboseErrorsPlugin

_TARGET = "https://example.com/"


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestPluginRun:
    async def test_python_stack_trace_is_medium(self) -> None:
        plugin = VerboseErrorsPlugin()
        body = (
            "Traceback (most recent call last):\n"
            '  File "/app/handler.py", line 42, in handle\n'
            "    result = do_something()\n"
            "ValueError: invalid input\n"
        )
        resp = FakeResponse(body=body, status=500)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        medium = _findings_with(findings, title_contains="stack trace")
        assert len(medium) == 1
        assert medium[0].severity is Severity.MEDIUM
        assert medium[0].confidence is Confidence.FIRM

    async def test_php_warning_is_medium(self) -> None:
        plugin = VerboseErrorsPlugin()
        body = "PHP Warning: include(/app/config.php): failed to open stream" + " " * 50
        resp = FakeResponse(body=body, status=200)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 1
        assert findings[0].severity is Severity.MEDIUM

    async def test_spring_boot_whitelabel(self) -> None:
        plugin = VerboseErrorsPlugin()
        body = "Whitelabel Error Page" + " " * 50
        resp = FakeResponse(body=body, status=500)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 1
        assert findings[0].severity is Severity.MEDIUM

    async def test_debug_marker_is_low_info(self) -> None:
        plugin = VerboseErrorsPlugin()
        body = "<html><body>APP_DEBUG=true" + " " * 50 + "</body></html>"
        resp = FakeResponse(body=body, status=200)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        low = _findings_with(findings, title_contains="Debug mode")
        assert len(low) == 1
        assert low[0].severity is Severity.LOW
        assert low[0].confidence is Confidence.INFORMATIONAL

    async def test_no_errors_no_finding(self) -> None:
        plugin = VerboseErrorsPlugin()
        body = "<html><body><h1>Welcome</h1><p>Hello world.</p></body></html>"
        resp = FakeResponse(body=body, status=200)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_short_body_skipped(self) -> None:
        plugin = VerboseErrorsPlugin()
        resp = FakeResponse(body="ok", status=200)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_network_error_returns_empty(self) -> None:
        plugin = VerboseErrorsPlugin()

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

    async def test_multiple_frameworks_detected(self) -> None:
        plugin = VerboseErrorsPlugin()
        body = (
            "Traceback (most recent call last):\n"
            '  File "/app/handler.py", line 42\n'
            "django.core.exceptions.ImproperlyConfigured: settings\n"
            + " " * 50
        )
        resp = FakeResponse(body=body, status=500)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 1
        frameworks = findings[0].evidence["frameworks"]
        assert "Python" in frameworks
        assert "Django" in frameworks
