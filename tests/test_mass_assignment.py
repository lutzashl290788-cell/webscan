"""Tests for the mass_assignment plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.mass_assignment import (
    MassAssignmentPlugin,
    _field_in_response,
    _is_api_endpoint,
)

_TARGET = "https://example.com/api/users/123"

class _GetPutSession:
    def __init__(self, get_resp: FakeResponse, put_resp: FakeResponse) -> None:
        self._get = get_resp
        self._put = put_resp
    def get(self, url: str, **_kw: object) -> FakeResponse:
        return self._get
    def post(self, url: str, **_kw: object) -> FakeResponse:
        return self._put
    def put(self, url: str, **_kw: object) -> FakeResponse:
        return self._put

def _findings_with(findings: list, *, title_contains: str) -> list:
    return [x for x in findings if title_contains.lower() in x.title.lower()]

class TestIsApiEndpoint:
    def test_api_path(self) -> None:
        assert _is_api_endpoint("https://example.com/api/users/123") is True
    def test_non_api(self) -> None:
        assert _is_api_endpoint("https://example.com/blog/post-1") is False

class TestFieldInResponse:
    def test_json_string(self) -> None:
        assert _field_in_response('{"role": "admin"}', "role", "admin") is True
    def test_json_bool(self) -> None:
        assert _field_in_response('{"is_admin": true}', "is_admin", "true") is True
    def test_not_present(self) -> None:
        assert _field_in_response('{"name": "alice"}', "role", "admin") is False

class TestPluginRun:
    async def test_critical_when_role_accepted(self) -> None:
        plugin = MassAssignmentPlugin()
        get_resp = FakeResponse(
            body='{"id":123,"name":"Alice","role":"user"}' + " " * 50,
            status=200,
        )
        put_resp = FakeResponse(body='{"id":123,"name":"Alice","role":"admin"}', status=200)
        session = _GetPutSession(get_resp, put_resp)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        high = _findings_with(findings, title_contains="Mass assignment")
        assert len(high) == 1
        assert high[0].severity is Severity.HIGH
        assert high[0].confidence is Confidence.TENTATIVE

    async def test_no_finding_when_rejected(self) -> None:
        plugin = MassAssignmentPlugin()
        get_resp = FakeResponse(
            body='{"id":123,"name":"Alice","role":"user"}' + " " * 50,
            status=200,
        )
        put_resp = FakeResponse(body='{"error":"forbidden"}', status=403)
        session = _GetPutSession(get_resp, put_resp)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_non_api_skipped(self) -> None:
        plugin = MassAssignmentPlugin()
        resp = FakeResponse(body='<html>blog post</html>', status=200)
        findings = await plugin.run("https://example.com/blog/post-1", FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []
