"""Tests for the host_header_injection plugin."""
from __future__ import annotations

from typing import Any

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.host_header_injection import (
    HostHeaderInjectionPlugin,
    _compile_url_patterns,
    _find_url_reflection,
    _has_plain_reflection,
    _is_reset_endpoint,
)

_TARGET = "https://example.com/reset"


# ─── Fake session that supports custom request headers ──────────────────────


class _HeaderAwareSession:
    """Returns one response for the baseline (no extra header), another when
    a specific extra header is present in the request."""

    def __init__(
        self,
        baseline: FakeResponse,
        probe: FakeResponse,
        trigger_header: str,
    ) -> None:
        self._baseline = baseline
        self._probe = probe
        self._trigger_header = trigger_header.lower()
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        headers = kwargs.get("headers") or {}
        if isinstance(headers, dict):
            for k in headers:
                if k.lower() == self._trigger_header:
                    return self._probe
        return self._baseline


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestIsResetEndpoint:
    def test_reset_path(self) -> None:
        assert _is_reset_endpoint("https://example.com/reset") is True

    def test_reset_password_path(self) -> None:
        assert _is_reset_endpoint("https://example.com/reset-password") is True

    def test_forgot_password_path(self) -> None:
        assert _is_reset_endpoint("https://example.com/forgot") is True
        assert _is_reset_endpoint("https://example.com/forgot-password") is True

    def test_password_reset_path(self) -> None:
        assert _is_reset_endpoint("https://example.com/password-reset") is True

    def test_account_recover_path(self) -> None:
        assert _is_reset_endpoint("https://example.com/account/recover") is True

    def test_wordpress_lostpassword(self) -> None:
        assert _is_reset_endpoint(
            "https://example.com/wp-login.php?action=lostpassword"
        ) is True

    def test_non_reset_path(self) -> None:
        assert _is_reset_endpoint("https://example.com/") is False
        assert _is_reset_endpoint("https://example.com/login") is False
        assert _is_reset_endpoint("https://example.com/api/users") is False

    def test_reset_in_middle_of_path(self) -> None:
        # /account/reset/confirm/123 — should match
        assert _is_reset_endpoint("https://example.com/account/reset/confirm/123") is True


class TestFindUrlReflection:
    def test_https_url_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<a href="https://{sentinel}/reset?token=abc">Click</a>'
        hits = _find_url_reflection(body, sentinel)
        assert len(hits) >= 1

    def test_protocol_relative_url(self) -> None:
        sentinel = "evil.example"
        body = f'<a href="//{sentinel}/reset">Click</a>'
        hits = _find_url_reflection(body, sentinel)
        assert len(hits) >= 1

    def test_href_attribute_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<link rel="canonical" href="https://{sentinel}/page">'
        hits = _find_url_reflection(body, sentinel)
        assert len(hits) >= 1

    def test_json_url_field(self) -> None:
        sentinel = "evil.example"
        body = f'{{"reset_url": "https://{sentinel}/reset?token=abc"}}'
        hits = _find_url_reflection(body, sentinel)
        assert len(hits) >= 1

    def test_no_url_reflection(self) -> None:
        sentinel = "evil.example"
        body = "<html><body><p>Visit us for help.</p></body></html>"
        hits = _find_url_reflection(body, sentinel)
        assert hits == []

    def test_plain_text_not_url_reflection(self) -> None:
        """Sentinel in plain text (not in URL) → not a URL reflection."""
        sentinel = "evil.example"
        body = "<html><body><p>Server: evil.example</p></body></html>"
        hits = _find_url_reflection(body, sentinel)
        assert hits == []


class TestHasPlainReflection:
    def test_present(self) -> None:
        assert _has_plain_reflection("hello evil.example world", "evil.example") is True

    def test_absent(self) -> None:
        assert _has_plain_reflection("nothing here", "evil.example") is False


class TestCompileUrlPatterns:
    def test_returns_compiled_patterns(self) -> None:
        patterns = _compile_url_patterns("evil.example")
        assert len(patterns) > 0
        for p in patterns:
            assert hasattr(p, "search")


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestPluginRun:
    async def test_non_reset_endpoint_skipped(self) -> None:
        """Only password-reset endpoints are probed — skip everything else."""
        plugin = HostHeaderInjectionPlugin()
        baseline = FakeResponse(body="<html><body>Home page</body></html>", status=200)
        session = FakeSession(baseline)
        findings = await plugin.run(
            "https://example.com/", session  # type: ignore[arg-type]
        )
        assert findings == []

    async def test_url_reflection_is_critical(self) -> None:
        """Sentinel in href URL → CRITICAL FIRM."""
        plugin = HostHeaderInjectionPlugin()
        baseline_body = (
            "<html><body><h1>Reset Password</h1>"
            '<p>Enter your email: <a href="https://example.com/reset?token=abc">Reset</a></p>'
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_body = (
            "<html><body><h1>Reset Password</h1>"
            '<p>Enter your email: <a href="https://webscan-reset-probe-SENTINEL.example/reset?token=abc">Reset</a></p>'
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "SENTINEL"  # type: ignore[assignment]
        try:
            probe_resp = FakeResponse(body=probe_body, status=200)
            session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
            findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

            critical = _findings_with(findings, title_contains="URL reflection")
            assert len(critical) == 1
            assert critical[0].severity is Severity.CRITICAL
            assert critical[0].confidence is Confidence.FIRM
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_plain_reflection_is_high_tentative(self) -> None:
        """Sentinel in body (not URL) → HIGH TENTATIVE."""
        plugin = HostHeaderInjectionPlugin()
        baseline_body = (
            "<html><body><h1>Reset Password</h1>"
            "<p>Enter your email address below.</p>"
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(body=baseline_body, status=200)
        # Probe has sentinel in plain text, not in a URL
        probe_body = (
            "<html><body><h1>Reset Password</h1>"
            "<p>Server: webscan-reset-probe-SENTINEL.example</p>"
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "SENTINEL"  # type: ignore[assignment]
        try:
            probe_resp = FakeResponse(body=probe_body, status=200)
            session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
            findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

            high = _findings_with(findings, title_contains="plain reflection")
            assert len(high) == 1
            assert high[0].severity is Severity.HIGH
            assert high[0].confidence is Confidence.TENTATIVE
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_no_reflection_but_accepted_is_info(self) -> None:
        """Server accepts header (200) but doesn't reflect it → INFO."""
        plugin = HostHeaderInjectionPlugin()
        body = (
            "<html><body><h1>Reset Password</h1>"
            "<p>Enter your email address below to receive a reset link.</p>"
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(body=body, status=200)
        # Probe returns the SAME body — no reflection.
        probe_resp = FakeResponse(body=body, status=200)
        session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        info = _findings_with(findings, title_contains="blind poisoning")
        assert len(info) == 1
        assert info[0].severity is Severity.INFO

    async def test_404_response_no_finding(self) -> None:
        """4xx response means the endpoint rejected the request — no finding."""
        plugin = HostHeaderInjectionPlugin()
        baseline = FakeResponse(body="Not Found", status=404)
        probe_resp = FakeResponse(body="Bad Request", status=400)
        session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_network_error_returns_empty(self) -> None:
        plugin = HostHeaderInjectionPlugin()

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

    async def test_evidence_includes_injected_header(self) -> None:
        """CRITICAL finding evidence records which header was injected."""
        plugin = HostHeaderInjectionPlugin()
        baseline_body = (
            "<html><body><h1>Reset Password</h1>"
            '<p><a href="https://example.com/reset?token=abc">Reset</a></p>'
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(body=baseline_body, status=200)
        probe_body = (
            "<html><body><h1>Reset Password</h1>"
            '<p><a href="https://webscan-reset-probe-SENTINEL.example/reset?token=abc">Reset</a></p>'
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "SENTINEL"  # type: ignore[assignment]
        try:
            probe_resp = FakeResponse(body=probe_body, status=200)
            session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
            findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
            crit = _findings_with(findings, title_contains="URL reflection")[0]
            ev = crit.evidence
            assert ev["injected_header"] == "X-Forwarded-Host"
            assert "webscan-reset-probe" in str(ev["injected_value"])
            assert "url_matches" in ev
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_wordpress_lostpassword_endpoint_detected(self) -> None:
        """WordPress wp-login.php?action=lostpassword should be detected."""
        plugin = HostHeaderInjectionPlugin()
        body = (
            "<html><body><h1>Lost Password</h1>"
            "<p>Enter your username or email to reset your password.</p>"
            "<p>Additional content for body length here.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(body=body, status=200)
        probe_resp = FakeResponse(body=body, status=200)  # No reflection
        session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
        findings = await plugin.run(
            "https://example.com/wp-login.php?action=lostpassword",
            session,  # type: ignore[arg-type]
        )
        # Should produce an INFO finding (blind poisoning) since the endpoint
        # accepted the header but didn't reflect it.
        info = _findings_with(findings, title_contains="blind poisoning")
        assert len(info) == 1
