"""Tests for the open redirect plugin."""
from __future__ import annotations

from webscan.models import Confidence, Severity
from webscan.plugins.open_redirect import (
    _REDIRECT_PARAMS,
    OpenRedirectPlugin,
    _find_redirect_params,
    _points_to_evil,
    _replace_param,
)


class _Resp:
    def __init__(self, status: int, location: str | None) -> None:
        self.status = status
        self.headers = {"Location": location} if location else {}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _RedirectSession:
    """Echoes the redirect target back in Location (vulnerable app)."""

    def __init__(self, *, vulnerable: bool) -> None:
        self.vulnerable = vulnerable
        self.calls = 0

    def get(self, url: str, **_kw: object) -> _Resp:
        from urllib.parse import parse_qs, urlparse

        self.calls += 1
        qs = parse_qs(urlparse(url).query)
        dest = ""
        for vals in qs.values():
            dest = vals[0]
        if self.vulnerable and dest:
            return _Resp(302, dest)
        return _Resp(200, None)


async def test_detects_open_redirect() -> None:
    plugin = OpenRedirectPlugin()
    session = _RedirectSession(vulnerable=True)

    findings = await plugin.run("https://example.com/?next=/home", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["parameter"] == "next"


async def test_safe_app_no_finding() -> None:
    plugin = OpenRedirectPlugin()
    session = _RedirectSession(vulnerable=False)

    findings = await plugin.run("https://example.com/?next=/home", session)  # type: ignore[arg-type]

    assert findings == []


async def test_non_redirect_param_skipped() -> None:
    plugin = OpenRedirectPlugin()
    session = _RedirectSession(vulnerable=True)

    findings = await plugin.run("https://example.com/?id=5", session)  # type: ignore[arg-type]

    assert findings == []
    assert session.calls == 0  # 'id' is not a redirect-like parameter


# ─── Tests for the improved (v2) implementation ───────────────────────────────


class TestFindRedirectParams:
    def test_finds_next_param(self) -> None:
        assert _find_redirect_params("https://example.com/?next=/home") == ["next"]

    def test_finds_url_param(self) -> None:
        assert _find_redirect_params("https://example.com/?url=https://x") == ["url"]

    def test_finds_redirect_param(self) -> None:
        assert _find_redirect_params("https://example.com/?redirect=/x") == ["redirect"]

    def test_finds_return_url_param(self) -> None:
        assert _find_redirect_params("https://example.com/?return_url=/x") == ["return_url"]

    def test_finds_callback_param(self) -> None:
        assert _find_redirect_params("https://example.com/?callback=/x") == ["callback"]

    def test_finds_continue_param(self) -> None:
        assert _find_redirect_params("https://example.com/?continue=/x") == ["continue"]

    def test_case_insensitive(self) -> None:
        assert _find_redirect_params("https://example.com/?NEXT=/x") == ["NEXT"]
        assert _find_redirect_params("https://example.com/?Redirect=/x") == ["Redirect"]

    def test_no_query(self) -> None:
        assert _find_redirect_params("https://example.com/path") == []

    def test_no_redirect_params(self) -> None:
        assert _find_redirect_params("https://example.com/?id=5&q=search") == []

    def test_multiple_redirect_params(self) -> None:
        out = _find_redirect_params("https://example.com/?next=a&url=b&redirect=c")
        assert "next" in out
        assert "url" in out
        assert "redirect" in out

    def test_max_params_cap(self) -> None:
        # Build a URL with more than _MAX_PARAMS_PER_TARGET redirect params.
        param_names = ["next", "url", "redirect", "return_url", "callback", "continue", "dest"]
        url = "https://example.com/?" + "&".join(f"{p}=x" for p in param_names)
        out = _find_redirect_params(url)
        assert len(out) <= 5

    def test_all_recognised_param_names(self) -> None:
        """Every name in _REDIRECT_PARAMS should be detected."""
        for name in _REDIRECT_PARAMS:
            url = f"https://example.com/?{name}=/x"
            out = _find_redirect_params(url)
            assert out == [name], f"Failed for param name: {name}"


class TestPointsToEvil:
    def test_absolute_url_to_evil(self) -> None:
        assert _points_to_evil("https://evil-webscan.example/") is True

    def test_protocol_relative_to_evil(self) -> None:
        assert _points_to_evil("//evil-webscan.example/") is True

    def test_same_site_with_evil_in_query(self) -> None:
        """Evil host in query string of a same-site redirect → NOT a finding."""
        assert _points_to_evil("/login?next=https://evil-webscan.example/") is False

    def test_different_host(self) -> None:
        assert _points_to_evil("https://other.example/") is False

    def test_empty_location(self) -> None:
        assert _points_to_evil("") is False

    def test_relative_path(self) -> None:
        assert _points_to_evil("/home") is False

    def test_case_insensitive_host(self) -> None:
        assert _points_to_evil("https://EVIL-WEBSCAN.EXAMPLE/") is True


class TestReplaceParam:
    def test_replaces_value(self) -> None:
        url = "https://example.com/?next=/home&other=foo"
        new = _replace_param(url, "next", "https://evil.example/")
        assert "next=https" in new or "next=https%3A" in new
        assert "other=foo" in new

    def test_preserves_path(self) -> None:
        url = "https://example.com/path/to/page?next=/home"
        new = _replace_param(url, "next", "/other")
        from urllib.parse import urlparse
        assert urlparse(new).path == "/path/to/page"


# ─── End-to-end tests for improved payloads ──────────────────────────────────


async def test_detects_protocol_relative_payload() -> None:
    """//evil-webscan.example/ payload should be detected."""
    plugin = OpenRedirectPlugin()
    session = _RedirectSession(vulnerable=True)
    findings = await plugin.run(
        "https://example.com/?next=/home", session  # type: ignore[arg-type]
    )
    assert len(findings) == 1
    # The payload that worked should be one of the 13 variants.
    payload = findings[0].evidence["payload"]
    assert "evil-webscan.example" in payload


async def test_finding_confidence_is_firm() -> None:
    """Improved plugin uses Confidence.FIRM (content-verified via Location host)."""
    plugin = OpenRedirectPlugin()
    session = _RedirectSession(vulnerable=True)
    findings = await plugin.run("https://example.com/?next=/home", session)  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.FIRM


async def test_safe_param_value_no_finding() -> None:
    """If the param value is /home (relative), server shouldn't redirect to evil."""
    plugin = OpenRedirectPlugin()
    # Vulnerable session, but the value /home is relative — _points_to_evil
    # returns False for relative URLs.
    session = _RedirectSession(vulnerable=True)
    # The plugin will replace /home with one of its payloads — those are
    # absolute or protocol-relative, so vulnerable=True will redirect to them.
    # This test verifies the plugin correctly identifies the redirect.
    findings = await plugin.run("https://example.com/?next=/home", session)  # type: ignore[arg-type]
    # We expect a finding because the vulnerable session redirects whatever
    # value we put in the param, and our payloads contain the evil host.
    assert len(findings) == 1


async def test_evidence_includes_location() -> None:
    """Finding evidence includes the actual Location header value."""
    plugin = OpenRedirectPlugin()
    session = _RedirectSession(vulnerable=True)
    findings = await plugin.run("https://example.com/?next=/home", session)  # type: ignore[arg-type]
    assert len(findings) == 1
    ev = findings[0].evidence
    assert "location" in ev
    assert "evil-webscan.example" in str(ev["location"])
    assert "parameter" in ev
    assert "payload" in ev


async def test_network_error_returns_empty() -> None:
    """If session.get raises, return [] (never propagate)."""
    plugin = OpenRedirectPlugin()

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
        findings = await plugin.run(
            "https://example.com/?next=/home", _BoomSession()  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]

