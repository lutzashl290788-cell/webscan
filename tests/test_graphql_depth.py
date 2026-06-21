"""Tests for the graphql_depth plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.graphql_depth import GraphqlDepthPlugin

_TARGET = "https://example.com/graphql"

class _GetPostSession:
    def __init__(self, get_resp: FakeResponse, post_resp: FakeResponse) -> None:
        self._get = get_resp
        self._post = post_resp
    def get(self, url: str, **_kw: object) -> FakeResponse:
        return self._get
    def post(self, url: str, **_kw: object) -> FakeResponse:
        return self._post

def _findings_with(findings: list, *, title_contains: str) -> list:
    return [x for x in findings if title_contains.lower() in x.title.lower()]

class TestPluginRun:
    async def test_depth_attack_detected(self) -> None:
        plugin = GraphqlDepthPlugin()
        post_resp = FakeResponse(body='{"data":{"hero":{"name":"Luke"}}}' + " " * 20, status=200)
        session = _GetPostSession(FakeResponse(body="", status=200), post_resp)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        depth = _findings_with(findings, title_contains="depth attack")
        assert len(depth) == 1
        assert depth[0].severity is Severity.MEDIUM

    async def test_field_suggestion_detected(self) -> None:
        plugin = GraphqlDepthPlugin()
        # First POST = depth probe (returns 400 to skip), second = suggestion probe
        responses = [
            FakeResponse(body='{"errors":[{"message":"depth exceeded"}]}', status=400),
            FakeResponse(body='{"errors":[{"message":"Did you mean \\"hero\\"?"}]}', status=200),
        ]
        call_count = [0]
        class _Session:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="", status=200)
            def post(self, url: str, **_kw: object) -> FakeResponse:
                if call_count[0] < len(responses):
                    r = responses[call_count[0]]
                    call_count[0] += 1
                    return r
                return FakeResponse(body="", status=400)
        findings = await plugin.run(_TARGET, _Session())  # type: ignore[arg-type]
        suggest = _findings_with(findings, title_contains="field suggestion")
        assert len(suggest) == 1

    async def test_non_graphql_skipped(self) -> None:
        plugin = GraphqlDepthPlugin()
        resp = FakeResponse(body="<html>not graphql</html>", status=200)
        findings = await plugin.run("https://example.com/api/users", FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []


class TestCoverageGaps:
    async def test_post_network_error_returns_empty(self) -> None:
        """Lines 123-124: a transport error on the POST probe yields no finding."""
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
            def get(self, _url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="", status=200)

            def post(self, _url: str, **_kw: object) -> _RaisingResp:
                return _RaisingResp()

        orig = aiohttp.ClientError
        aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
        try:
            plugin = GraphqlDepthPlugin()
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_depth_probe_empty_body_skipped(self) -> None:
        """Depth probe returns 200 but body below _MIN_BODY_LENGTH → no finding."""
        plugin = GraphqlDepthPlugin()
        post_resp = FakeResponse(body="x", status=200)  # < 20 chars
        suggest_resp = FakeResponse(body='{"errors":[]}', status=200)
        responses = [post_resp, suggest_resp]
        call_count = [0]

        class _Session:
            def get(self, _url: str, **_kw: object) -> FakeResponse:
                return FakeResponse(body="", status=200)

            def post(self, _url: str, **_kw: object) -> FakeResponse:
                if call_count[0] < len(responses):
                    r = responses[call_count[0]]
                    call_count[0] += 1
                    return r
                return FakeResponse(body="", status=400)

        findings = await plugin.run(_TARGET, _Session())  # type: ignore[arg-type]
        depth = _findings_with(findings, title_contains="depth attack")
        assert depth == []
