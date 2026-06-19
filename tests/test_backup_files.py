"""Tests for the backup_files plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse
from webscan.models import Confidence, Severity
from webscan.plugins.backup_files import BackupFilesPlugin, _has_source_marker

_TARGET = "https://example.com/"


class _CalibrationSession:
    """Returns 404 for soft-404 calibration, and mapped responses for probes."""

    def __init__(self, probes: dict[str, FakeResponse]) -> None:
        self._probes = probes

    def get(self, url: str, **_kw: object) -> FakeResponse:
        if "webscan-soft404-probe" in url:
            return FakeResponse(body="", status=404)
        if url in self._probes:
            return self._probes[url]
        return FakeResponse(body="Not Found", status=404)


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestHasSourceMarker:
    def test_php_open_tag(self) -> None:
        assert _has_source_marker("<?php echo 'hi';") is True

    def test_define(self) -> None:
        assert _has_source_marker("define('DB_HOST', 'localhost');") is True

    def test_password(self) -> None:
        assert _has_source_marker("password = secret123") is True

    def test_no_markers(self) -> None:
        assert _has_source_marker("<html><body>Hello</body></html>") is False


class TestPluginRun:
    async def test_critical_when_source_leaks(self) -> None:
        plugin = BackupFilesPlugin()
        probe_body = (
            "<?php define('DB_PASSWORD', 'secret'); "
            "$conn = mysqli_connect(DB_HOST, DB_USER);"
        )
        session = _CalibrationSession({
            "https://example.com/config.php.bak": FakeResponse(body=probe_body, status=200),
        })
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        critical = _findings_with(findings, title_contains="leaks source")
        assert len(critical) == 1
        assert critical[0].severity is Severity.CRITICAL
        assert critical[0].confidence is Confidence.FIRM

    async def test_medium_when_no_source_markers(self) -> None:
        plugin = BackupFilesPlugin()
        session = _CalibrationSession({
            "https://example.com/config.php.bak": FakeResponse(body="x" * 100, status=200),
        })
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        medium = _findings_with(findings, title_contains="Exposed backup")
        assert len(medium) == 1
        assert medium[0].severity is Severity.MEDIUM
        assert medium[0].confidence is Confidence.TENTATIVE

    async def test_no_finding_when_404(self) -> None:
        plugin = BackupFilesPlugin()
        session = _CalibrationSession({})
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_short_body(self) -> None:
        plugin = BackupFilesPlugin()
        session = _CalibrationSession({
            "https://example.com/config.php.bak": FakeResponse(body="ok", status=200),
        })
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_network_error_returns_empty(self) -> None:
        plugin = BackupFilesPlugin()

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
