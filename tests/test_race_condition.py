"""Tests for the race_condition plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.race_condition import RaceConditionPlugin

_TARGET = "https://example.com/api/apply?coupon=SAVE50"

def _findings_with(findings: list, *, title_contains: str) -> list:
    return [x for x in findings if title_contains.lower() in x.title.lower()]

class TestPluginRun:
    async def test_race_detected_when_multiple_success(self) -> None:
        plugin = RaceConditionPlugin()
        resp = FakeResponse(body='{"status":"success","message":"Coupon applied"}', status=200)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        race = _findings_with(findings, title_contains="Race condition")
        assert len(race) == 1
        assert race[0].severity is Severity.HIGH

    async def test_no_race_when_single_success(self) -> None:
        plugin = RaceConditionPlugin()
        # Only 1 response says success, others say error
        responses = [FakeResponse(body='{"status":"success"}',
            status=200)] + [FakeResponse(body='{"error":"already used"}', status=409)] * 9
        call_count = [0]
        class _Session:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                if call_count[0] < len(responses):
                    r = responses[call_count[0]]
                    call_count[0] += 1
                    return r
                return FakeResponse(body="", status=500)
        findings = await plugin.run(_TARGET, _Session())  # type: ignore[arg-type]
        race = _findings_with(findings, title_contains="Race condition")
        assert race == []

    async def test_non_race_param_skipped(self) -> None:
        plugin = RaceConditionPlugin()
        resp = FakeResponse(body='{"status":"ok"}', status=200)
        findings = await plugin.run("https://example.com/page?id=5",
            FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []


class TestCoverageGaps:
    """Targeted tests for uncovered branches."""

    async def test_no_query_string_skipped(self) -> None:
        """Line 45: _has_race_params returns False when there is no query string."""
        plugin = RaceConditionPlugin()
        resp = FakeResponse(body='{"status":"ok"}', status=200)
        # Target with no query → _has_race_params short-circuits on empty query.
        findings = await plugin.run(
            "https://example.com/api/apply", FakeSession(resp)  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_network_error_on_all_requests_no_finding(self) -> None:
        """Lines 74-75: a transport error on every concurrent request yields no finding."""
        import aiohttp

        class _ClientError(Exception):
            pass

        class _RaisingResp:
            async def __aenter__(self) -> _RaisingResp:
                raise _ClientError("boom")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _BoomSession:
            def get(self, _url: str, **_kw: object) -> _RaisingResp:
                return _RaisingResp()

        orig = aiohttp.ClientError
        aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
        try:
            plugin = RaceConditionPlugin()
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]
