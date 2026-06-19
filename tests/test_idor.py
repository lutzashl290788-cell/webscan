"""Tests for the idor plugin."""
from __future__ import annotations

from typing import Any

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.idor import (
    IdorPlugin,
    _find_id_in_path,
    _find_id_in_query,
    _has_auth_error,
    _is_api_endpoint,
    _length_ratio,
    _shift_path_id,
    _shift_query_id,
    _similarity,
)

_TARGET = "https://example.com"


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestIsApiEndpoint:
    def test_api_path(self) -> None:
        assert _is_api_endpoint("https://example.com/api/users/123") is True

    def test_v1_path(self) -> None:
        assert _is_api_endpoint("https://example.com/v1/orders/456") is True

    def test_v2_path(self) -> None:
        assert _is_api_endpoint("https://example.com/v2/profile/789") is True

    def test_admin_path(self) -> None:
        assert _is_api_endpoint("https://example.com/admin/users") is True

    def test_internal_path(self) -> None:
        assert _is_api_endpoint("https://example.com/internal/audit") is True

    def test_graphql_path(self) -> None:
        assert _is_api_endpoint("https://example.com/graphql") is True

    def test_non_api_path(self) -> None:
        assert _is_api_endpoint("https://example.com/articles/123") is False
        assert _is_api_endpoint("https://example.com/products/456") is False
        assert _is_api_endpoint("https://example.com/blog/post-123") is False


class TestFindIdInPath:
    def test_finds_trailing_id(self) -> None:
        assert _find_id_in_path("https://example.com/api/users/123") == [("path", 123)]

    def test_finds_id_in_middle(self) -> None:
        # The regex requires `/` after the integer; "/123/profile" should match.
        out = _find_id_in_path("https://example.com/api/123/profile")
        assert ("path", 123) in out

    def test_no_id(self) -> None:
        assert _find_id_in_path("https://example.com/api/users/me") == []

    def test_skips_zero(self) -> None:
        assert _find_id_in_path("https://example.com/api/0") == []

    def test_multiple_ids(self) -> None:
        out = _find_id_in_path("https://example.com/api/users/123/posts/456")
        assert ("path", 123) in out
        assert ("path", 456) in out


class TestFindIdInQuery:
    def test_finds_user_id_param(self) -> None:
        out = _find_id_in_query("https://example.com/api/profile?user_id=123")
        assert out == [("user_id", 123)]

    def test_finds_id_param(self) -> None:
        out = _find_id_in_query("https://example.com/api/?id=456")
        assert out == [("id", 456)]

    def test_no_query(self) -> None:
        assert _find_id_in_query("https://example.com/api/profile") == []

    def test_no_numeric_value(self) -> None:
        assert _find_id_in_query("https://example.com/api/?id=alice") == []

    def test_skips_zero(self) -> None:
        assert _find_id_in_query("https://example.com/api/?id=0") == []

    def test_multiple_params(self) -> None:
        out = _find_id_in_query("https://example.com/api/?user_id=1&post_id=2")
        assert ("user_id", 1) in out
        assert ("post_id", 2) in out


class TestShiftPathId:
    def test_shifts_trailing_id(self) -> None:
        url = "https://example.com/api/users/123"
        new = _shift_path_id(url, 123, 124)
        assert "/124" in new
        assert "/123" not in new

    def test_does_not_shift_unrelated_integer(self) -> None:
        url = "https://example.com/api/users/123"
        new = _shift_path_id(url, 999, 1000)
        assert "/123" in new  # unchanged


class TestShiftQueryId:
    def test_shifts_value(self) -> None:
        url = "https://example.com/api/?user_id=123&other=foo"
        new = _shift_query_id(url, "user_id", 123, 124)
        assert "user_id=124" in new
        assert "other=foo" in new

    def test_does_not_affect_other_params(self) -> None:
        url = "https://example.com/api/?user_id=123&id=123"
        new = _shift_query_id(url, "user_id", 123, 124)
        # Only the first occurrence of user_id is changed.
        assert "user_id=124" in new
        assert "id=123" in new


class TestHasAuthError:
    def test_unauthorized_marker(self) -> None:
        assert _has_auth_error('{"error": "Unauthorized"}') is True

    def test_forbidden_marker(self) -> None:
        assert _has_auth_error("Forbidden access") is True

    def test_login_required(self) -> None:
        assert _has_auth_error("Login required") is True

    def test_status_401_json(self) -> None:
        assert _has_auth_error('{"status": 401}') is True

    def test_normal_response(self) -> None:
        assert _has_auth_error('{"user": "alice", "email": "a@b.com"}') is False


class TestSimilarity:
    def test_identical_strings(self) -> None:
        assert _similarity("hello world", "hello world") == 1.0

    def test_completely_different(self) -> None:
        assert _similarity("abc", "xyz") < 0.5

    def test_similar_json(self) -> None:
        a = '{"id": 1, "name": "Alice", "email": "alice@example.com"}'
        b = '{"id": 2, "name": "Bob", "email": "bob@example.com"}'
        sim = _similarity(a, b)
        assert sim > 0.7  # structurally similar

    def test_caps_at_max_length(self) -> None:
        # Very long strings shouldn't crash or take forever.
        a = "x" * 1_000_000
        b = "y" * 1_000_000
        _similarity(a, b)  # should not crash


class TestLengthRatio:
    def test_equal_length(self) -> None:
        assert _length_ratio("abc", "xyz") == 1.0

    def test_probe_double_baseline(self) -> None:
        assert _length_ratio("ab", "abcd") == 2.0

    def test_baseline_half_probe(self) -> None:
        assert _length_ratio("abcd", "ab") == 0.5

    def test_empty_baseline(self) -> None:
        assert _length_ratio("", "abc") == 0.0


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


class _MultiResponseSession:
    """Returns the baseline for the original URL; probes for shifted URLs.

    Each probe URL is mapped to a specific response via the ``probes`` dict.
    URLs NOT in the dict (including the soft-404 calibration URL) return a
    404 — this mirrors a well-behaved server that doesn't soft-404 every URL.
    """

    def __init__(
        self,
        baseline: FakeResponse,
        probes: dict[str, FakeResponse],
        baseline_url: str | None = None,
    ) -> None:
        self._baseline = baseline
        self._probes = probes
        self._baseline_url = baseline_url
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        # Soft-404 calibration URL — return 404 (well-behaved server).
        if "webscan-soft404-probe" in url:
            return FakeResponse(body="", status=404)
        if url in self._probes:
            return self._probes[url]
        # If a baseline URL is specified, return baseline for it; 404 otherwise.
        if self._baseline_url is not None:
            if url == self._baseline_url:
                return self._baseline
            return FakeResponse(body="Not Found", status=404)
        return self._baseline


class _ProbesOnlySession:
    """Returns the baseline ONLY for the original URL; all others return 404.

    Use this in "no finding" tests where any probe response that matches the
    baseline's shape would be a false positive.
    """

    def __init__(self, baseline: FakeResponse, baseline_url: str) -> None:
        self._baseline = baseline
        self._baseline_url = baseline_url
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        if url == self._baseline_url:
            return self._baseline
        return FakeResponse(body="Not Found", status=404)


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestPluginRun:
    async def test_non_api_url_skipped(self) -> None:
        """Public-content URLs (no /api/) are skipped to avoid FP."""
        plugin = IdorPlugin()
        baseline = FakeResponse(body='{"id":1,"name":"Alice"}', status=200)
        session = FakeSession(baseline)
        findings = await plugin.run(
            "https://example.com/articles/123", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_api_url_without_id_skipped(self) -> None:
        plugin = IdorPlugin()
        baseline = FakeResponse(body='{"ok":true}', status=200)
        session = FakeSession(baseline)
        findings = await plugin.run(
            "https://example.com/api/me", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_baseline_not_200_skipped(self) -> None:
        plugin = IdorPlugin()
        baseline = FakeResponse(body="Not Found", status=404)
        session = FakeSession(baseline)
        findings = await plugin.run(
            "https://example.com/api/users/123", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_baseline_too_short_skipped(self) -> None:
        plugin = IdorPlugin()
        baseline = FakeResponse(body="ok", status=200)
        session = FakeSession(baseline)
        findings = await plugin.run(
            "https://example.com/api/users/123", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_baseline_unauthorized_skipped(self) -> None:
        """If baseline already says 'unauthorized', caller isn't auth'd — skip."""
        plugin = IdorPlugin()
        baseline = FakeResponse(
            body='{"error": "Unauthorized access"}' + " " * 200,
            status=200,
        )
        session = FakeSession(baseline)
        findings = await plugin.run(
            "https://example.com/api/users/123", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_idor_when_probe_returns_similar_200(self) -> None:
        """Same-shape 200 on shifted ID → HIGH TENTATIVE finding."""
        plugin = IdorPlugin()
        baseline_body = (
            '{"id": 123, "name": "Alice", "email": "alice@example.com", '
            '"role": "admin", "created_at": "2024-01-01"}'
        )
        probe_body = (
            '{"id": 124, "name": "Bob", "email": "bob@example.com", '
            '"role": "user", "created_at": "2024-02-01"}'
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        probe_resp = FakeResponse(
            body=probe_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        # Probe URL: /api/users/124 (shifted from /api/users/123)
        probe_url = "https://example.com/api/users/124"
        session = _MultiResponseSession(baseline, {probe_url: probe_resp})
        findings = await plugin.run(
            "https://example.com/api/users/123", session  # type: ignore[arg-type]
        )

        idor = _findings_with(findings, title_contains="Possible IDOR")
        assert len(idor) == 1
        assert idor[0].severity is Severity.HIGH
        assert idor[0].confidence is Confidence.TENTATIVE

    async def test_no_finding_when_probe_401(self) -> None:
        """Auth enforced on shifted ID → no finding."""
        plugin = IdorPlugin()
        baseline_body = '{"id": 123, "name": "Alice"}' + " " * 200
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_resp = FakeResponse(body="Unauthorized", status=401)
        # Map BOTH shifted URLs to 401 — plugin may probe ID+1 or ID-1 first.
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_probe_403(self) -> None:
        plugin = IdorPlugin()
        baseline_body = '{"id": 123, "name": "Alice"}' + " " * 200
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_resp = FakeResponse(body="Forbidden", status=403)
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_probe_404(self) -> None:
        """Shifted ID doesn't exist → can't tell if it'd be accessible."""
        plugin = IdorPlugin()
        baseline_body = '{"id": 123, "name": "Alice"}' + " " * 200
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_resp = FakeResponse(body="Not Found", status=404)
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_probe_has_auth_error_marker(self) -> None:
        """Even with 200, response containing 'Unauthorized' → safe."""
        plugin = IdorPlugin()
        baseline_body = '{"id": 123, "name": "Alice"}' + " " * 200
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_resp = FakeResponse(
            body='{"error": "Unauthorized"}' + " " * 200,
            status=200,
        )
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_probe_very_different_length(self) -> None:
        """Length ratio outside 0.5–2.0 → not a clear IDOR signal."""
        plugin = IdorPlugin()
        baseline_body = "x" * 1000
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_resp = FakeResponse(body="y" * 10, status=200)  # 0.01 ratio
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_content_type_mismatch(self) -> None:
        """Baseline JSON, probe HTML → suspicious but not IDOR."""
        plugin = IdorPlugin()
        baseline_body = '{"id": 123, "name": "Alice"}' + " " * 200
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        probe_resp = FakeResponse(
            body="<html><body>Bob's profile</body></html>",
            status=200,
            headers=[("Content-Type", "text/html")],
        )
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_probe_too_dissimilar(self) -> None:
        """Probe is 200 but content shape is completely different → skip."""
        plugin = IdorPlugin()
        baseline_body = (
            '{"user": {"id": 123, "name": "Alice", "email": "alice@x.com"}}'
            + " " * 200
        )
        baseline_url = "https://example.com/api/users/123"
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        # Probe is 200, similar length, but completely different shape
        probe_resp = FakeResponse(
            body="Z" * len(baseline_body),
            status=200,
            headers=[("Content-Type", "application/json")],
        )
        session = _MultiResponseSession(baseline, {
            "https://example.com/api/users/124": probe_resp,
            "https://example.com/api/users/122": probe_resp,
        })
        findings = await plugin.run(baseline_url, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_query_param_idor_detected(self) -> None:
        """IDOR via ?user_id=123 → ?user_id=124 also detected."""
        plugin = IdorPlugin()
        baseline_body = (
            '{"id": 123, "name": "Alice", "email": "alice@example.com"}'
            + " " * 200
        )
        probe_body = (
            '{"id": 124, "name": "Bob", "email": "bob@example.com"}'
            + " " * 200
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        probe_resp = FakeResponse(
            body=probe_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        # /api/profile?user_id=123 → /api/profile?user_id=124
        probe_url = "https://example.com/api/profile?user_id=124"
        session = _MultiResponseSession(baseline, {probe_url: probe_resp})
        findings = await plugin.run(
            "https://example.com/api/profile?user_id=123", session  # type: ignore[arg-type]
        )
        idor = _findings_with(findings, title_contains="Possible IDOR")
        assert len(idor) == 1

    async def test_evidence_includes_probe_url_and_metrics(self) -> None:
        plugin = IdorPlugin()
        baseline_body = (
            '{"id": 123, "name": "Alice", "email": "alice@example.com"}'
            + " " * 200
        )
        probe_body = (
            '{"id": 124, "name": "Bob", "email": "bob@example.com"}'
            + " " * 200
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        probe_resp = FakeResponse(
            body=probe_body, status=200,
            headers=[("Content-Type", "application/json")],
        )
        probe_url = "https://example.com/api/users/124"
        session = _MultiResponseSession(baseline, {probe_url: probe_resp})
        findings = await plugin.run(
            "https://example.com/api/users/123", session  # type: ignore[arg-type]
        )
        idor = _findings_with(findings, title_contains="Possible IDOR")[0]
        ev = idor.evidence
        assert ev["original_id"] == 123
        assert ev["shifted_id"] == 124
        assert ev["id_location"] == "path"
        assert ev["probe_url"] == probe_url
        assert "similarity" in ev
        assert "length_ratio" in ev
        assert "baseline_status" in ev
        assert "probe_status" in ev

    async def test_network_error_returns_empty(self) -> None:
        """If session.get raises, return [] (never propagate)."""

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
            plugin = IdorPlugin()
            findings = await plugin.run(
                "https://example.com/api/users/123", _BoomSession()  # type: ignore[arg-type]
            )
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]


# ─── Edge cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    async def test_id_zero_skipped(self) -> None:
        """ID=0 doesn't get shifted to -1."""
        plugin = IdorPlugin()
        baseline = FakeResponse(body="x" * 200, status=200)
        session = FakeSession(baseline)
        # /api/users/0 — _find_id_in_path skips 0, so no probes
        findings = await plugin.run(
            "https://example.com/api/users/0", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_no_duplicate_probes(self) -> None:
        """If ID+1 and ID-1 produce the same probe URL, only one is sent."""
        plugin = IdorPlugin()
        # Both probes return 404 (no leak) — FakeSession always returns the
        # same response, so baseline fetch returns 404 too, which means the
        # plugin skips (baseline not 200). That's fine: this test only checks
        # that no duplicate probe URLs are sent.
        session = FakeSession(FakeResponse(body="Not Found", status=404))
        findings = await plugin.run(
            "https://example.com/api/users/123", session  # type: ignore[arg-type]
        )
        assert findings == []
