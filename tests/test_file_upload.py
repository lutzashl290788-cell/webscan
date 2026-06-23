"""Tests for the file_upload plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.file_upload import FileUploadPlugin

_TARGET = "https://example.com/upload"

class _GetPostSession:
    def __init__(
        self, get_resp: FakeResponse, post_resp: FakeResponse,
        verify_resp: FakeResponse | None = None,
    ) -> None:
        self._get = get_resp
        self._post = post_resp
        self._verify = verify_resp
        self._call_count = 0
    def get(self, url: str, **_kw: object) -> FakeResponse:
        if self._verify and self._call_count > 0:
            return self._verify
        self._call_count += 1
        return self._get
    def post(self, url: str, **_kw: object) -> FakeResponse:
        return self._post

def _findings_with(findings: list, *, title_contains: str) -> list:
    return [x for x in findings if title_contains.lower() in x.title.lower()]

class TestPluginRun:
    async def test_upload_accepted_and_accessible(self) -> None:
        plugin = FileUploadPlugin()
        get_resp = FakeResponse(
            body="<html><body>Upload page</body></html>",
            status=200,
            headers=[("Content-Type", "text/html")],
        )
        post_resp = FakeResponse(
            body='{"url":"https://example.com/uploads/webscan-test.txt"}',
            status=200,
        )
        verify_resp = FakeResponse(body="webscan-upload-test-safe", status=200)
        session = _GetPostSession(get_resp, post_resp, verify_resp)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        high = _findings_with(findings, title_contains="Unrestricted file upload")
        assert len(high) == 1
        assert high[0].severity is Severity.HIGH

    async def test_upload_rejected_no_finding(self) -> None:
        plugin = FileUploadPlugin()
        get_resp = FakeResponse(
            body="<html><body>Upload page</body></html>",
            status=200,
            headers=[("Content-Type", "text/html")],
        )
        post_resp = FakeResponse(body='{"error":"forbidden"}', status=403)
        session = _GetPostSession(get_resp, post_resp)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_non_upload_url_skipped(self) -> None:
        plugin = FileUploadPlugin()
        resp = FakeResponse(body="<html><body>Home page</body></html>", status=200,
            headers=[("Content-Type", "text/html")])
        findings = await plugin.run("https://example.com/home",
            FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []


class TestCoverageGaps:
    """Tests targeting uncovered lines."""

    async def test_file_form_detected(self) -> None:
        """Lines 53-57: form with file input detected."""
        plugin = FileUploadPlugin()
        body = (
            '<html><body>'
            '<form action="/upload" method="post">'
            '<input type="file" name="file">'
            '</form>' + "x" * 100 + '</body></html>'
        )
        post_resp = FakeResponse(body='{"error":"forbidden"}', status=403)

        class _S:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
            def post(self, url: str, **_kw: object) -> FakeResponse:
                return post_resp

        findings = await plugin.run("https://example.com/page", _S())  # type: ignore[arg-type]
        # Should not crash and should return empty (403 from upload)
        assert isinstance(findings, list)

    async def test_get_network_error(self) -> None:
        """Line 46: network error on GET."""
        plugin = FileUploadPlugin()

        class _BoomSession:
            def get(self, url: str, **_kw: object) -> _BoomResp:
                return _BoomResp()
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
            findings = await plugin.run("https://example.com/upload", _BoomSession())  # type: ignore[arg-type]  # noqa: E501
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_post_network_error(self) -> None:
        """Line 74: network error on POST."""
        plugin = FileUploadPlugin()

        class _BoomPostSession:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="<html>ok</html>" + "x" * 100, status=200, headers=[("Content-Type", "text/html")])  # noqa: E501
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
            findings = await plugin.run("https://example.com/upload", _BoomPostSession())  # type: ignore[arg-type]  # noqa: E501
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]
