"""Tests for security-hardening fixes (v2.5.1).

Covers the previously-untested branches added by the security audit:

* ``engine._build_redirect_safe_trace`` — auth-header strip on cross-origin
  redirect (CWE-200 / CWE-522).
* ``engine._same_host`` — host-equality helper used by the redirect hook.
* ``utils.http.same_origin`` / ``same_host`` — SSRF guards (CWE-918).
* ``registry._discover_plugins`` — supply-chain guard against a third-party
  plugin shadowing a built-in (CWE-1357).
* ``cli._mask_proxy_url`` — credentials redaction in stdout (CWE-532).
* ``registry.OPT_IN_PLUGINS`` — confirms state-changing plugins are opt-in.
"""
from __future__ import annotations

from typing import Any

import aiohttp
import pytest

from webscan import registry
from webscan.engine import _build_redirect_safe_trace, _same_host
from webscan.utils.http import same_host, same_origin

# ---------------------------------------------------------------------------
# engine._same_host / _build_redirect_safe_trace
# ---------------------------------------------------------------------------


def test_same_host_basic() -> None:
    assert _same_host("https://example.com/a", "https://example.com/b")
    # Different host => not same.
    assert not _same_host("https://example.com", "https://evil.com")
    # Case-insensitive host.
    assert _same_host("https://Example.COM", "https://example.com")
    # Scheme/port ignored — same host.
    assert _same_host("http://example.com", "https://example.com:8443")
    # Empty host on either side => False (we never treat '' as a host match).
    assert not _same_host("file:///etc/passwd", "https://example.com")


async def test_redirect_trace_strips_authorization_on_cross_origin_redirect() -> None:
    """The trace hook must drop Authorization when redirect host differs."""
    trace = _build_redirect_safe_trace()

    # Build a fake params object matching aiohttp.TraceRequestRedirectParams.
    # The real aiohttp class is a frozen attrs dataclass with .method, .url,
    # .headers, .response — we replicate the surface the hook reads.
    class _FakeResp:
        def __init__(self, location: str) -> None:
            self.headers = {"Location": location} if location else {}

    class _FakeParams:
        def __init__(self, original_url: str, location: str) -> None:
            self.url = aiohttp.client.URL(original_url)
            self.headers = aiohttp.typedefs.CIMultiDict()  # type: ignore[attr-defined]
            self.headers["Authorization"] = "Bearer secret"
            self.headers["Cookie"] = "session=abc"
            self.headers["User-Agent"] = "WebScan/test"
            self.response = _FakeResp(location)

    # Cross-origin redirect: auth headers must be stripped.
    p = _FakeParams("https://victim.com/login", "https://attacker.example/capture")
    for cb in trace.on_request_redirect:
        await cb(session=Any, trace_config_ctx=None, params=p)  # type: ignore[arg-type]
    assert "Authorization" not in p.headers
    assert "Cookie" not in p.headers
    # Non-sensitive headers stay.
    assert "User-Agent" in p.headers


async def test_redirect_trace_keeps_headers_on_same_origin_redirect() -> None:
    """Same-host redirect must keep all headers (cookies, auth) intact."""
    trace = _build_redirect_safe_trace()

    class _FakeResp:
        def __init__(self, location: str) -> None:
            self.headers = {"Location": location}

    class _FakeParams:
        def __init__(self) -> None:
            self.url = aiohttp.client.URL("https://example.com/login")
            self.headers = aiohttp.typedefs.CIMultiDict()  # type: ignore[attr-defined]
            self.headers["Authorization"] = "Bearer secret"
            self.response = _FakeResp("https://example.com/dashboard")

    p = _FakeParams()
    for cb in trace.on_request_redirect:
        await cb(session=Any, trace_config_ctx=None, params=p)  # type: ignore[arg-type]
    assert p.headers["Authorization"] == "Bearer secret"


async def test_redirect_trace_handles_missing_location_header() -> None:
    """A response with no Location header is a no-op (hook returns early)."""
    trace = _build_redirect_safe_trace()

    class _FakeResp:
        def __init__(self) -> None:
            self.headers = {}  # no Location

    class _FakeParams:
        def __init__(self) -> None:
            self.url = aiohttp.client.URL("https://example.com/a")
            self.headers = aiohttp.typedefs.CIMultiDict()  # type: ignore[attr-defined]
            self.headers["Authorization"] = "Bearer x"
            self.response = _FakeResp()

    p = _FakeParams()
    for cb in trace.on_request_redirect:
        await cb(session=Any, trace_config_ctx=None, params=p)  # type: ignore[arg-type]
    # Nothing stripped because we couldn't determine the redirect target.
    assert p.headers["Authorization"] == "Bearer x"


async def test_engine_actually_uses_trace_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live integration: ScanEngine must pass trace_configs to ClientSession."""
    from webscan.engine import ScanEngine

    captured: dict[str, Any] = {}

    class _FakeSession:
        def __init__(self, *a: Any, **kw: Any) -> None:
            captured["trace_configs"] = kw.get("trace_configs")
            # Provide the async-context-manager surface used by scan_all.
            self._connector = a[0] if a else None

        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

    # Patch ClientSession to capture kwargs without doing real network IO.
    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)

    eng = ScanEngine(plugins=[], concurrency=1, timeout=1)
    # We only need to enter scan_all far enough for ClientSession() to be built;
    # the empty targets list means no requests are issued.
    await eng.scan_all([])
    assert captured.get("trace_configs"), "ScanEngine must pass trace_configs to ClientSession"


# ---------------------------------------------------------------------------
# utils.http.same_origin / same_host
# ---------------------------------------------------------------------------


def test_same_origin_examples() -> None:
    assert same_origin("https://example.com/a", "https://example.com/b")
    # Different scheme => not same origin.
    assert not same_origin("https://example.com", "http://example.com")
    # Different host => not same origin.
    assert not same_origin("https://example.com", "https://evil.com")
    # Different port => not same origin.
    assert not same_origin("https://example.com", "https://example.com:8443")


def test_same_host_examples() -> None:
    assert same_host("http://example.com", "https://example.com:8443")
    assert not same_host("https://example.com", "https://evil.com")
    assert not same_host("file:///etc/passwd", "https://example.com")


# ---------------------------------------------------------------------------
# registry._discover_plugins — supply-chain guard
# ---------------------------------------------------------------------------


def test_opt_in_plugins_includes_state_changing() -> None:
    """State-changing plugins must be opt-in (H-4)."""
    for name in ("mass_assignment", "race_condition", "request_smuggling"):
        assert name in registry.OPT_IN_PLUGINS, f"{name} should be opt-in"


def test_opt_in_plugins_still_includes_network_heavy() -> None:
    assert "cve_lookup" in registry.OPT_IN_PLUGINS
    assert "graphql" in registry.OPT_IN_PLUGINS


def test_default_plugins_excludes_state_changing() -> None:
    """DEFAULT_PLUGINS must not include the state-changing set."""
    for name in ("mass_assignment", "race_condition", "request_smuggling"):
        assert name not in registry.DEFAULT_PLUGINS


def test_discover_plugins_rejects_builtin_name_collision(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A third-party entry point colliding with a built-in name must be skipped."""
    from importlib.metadata import EntryPoint

    from webscan.plugins.base import BasePlugin

    # The malicious third-party plugin must be a real BasePlugin subclass —
    # otherwise the discovery loop filters it out on the isinstance check
    # before the name-collision guard fires.
    class _EvilPlugin(BasePlugin):
        name = "headers"
        description = "evil"

        async def run(self, target: str, session: Any) -> list[Any]:  # noqa: ANN401
            return []

    # EntryPoint is immutable, so subclass it to override .load().
    class _FakeEntryPoint(EntryPoint):
        def load(self) -> Any:  # type: ignore[override]
            return _EvilPlugin

    fake_ep = _FakeEntryPoint(
        name="headers",  # collides with a built-in
        value="evil_pkg:EvilPlugin",
        group="webscan.plugins",
    )

    class _FakeEntryPoints:
        def __call__(self, *a: Any, **kw: Any) -> list[EntryPoint]:
            return [fake_ep]

    # entry_points() returns a callable-like; patch the registry's import.
    monkeypatch.setattr(registry, "entry_points", _FakeEntryPoints())

    discovered = registry._discover_plugins()
    assert "headers" not in discovered, "third-party must not shadow built-in 'headers'"
    err = capsys.readouterr().err
    assert "ignoring third-party plugin 'headers'" in err


def test_discover_plugins_skips_bad_entry_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken entry point (.load() raises) is skipped without crashing."""
    from importlib.metadata import EntryPoint

    class _BoomEP(EntryPoint):
        def load(self) -> Any:  # type: ignore[override]
            raise ImportError("simulated broken plugin")

    boom = _BoomEP(name="ghost", value="ghost_pkg:Ghost", group="webscan.plugins")

    class _FakeEntryPoints:
        def __call__(self, *a: Any, **kw: Any) -> list[EntryPoint]:
            return [boom]

    monkeypatch.setattr(registry, "entry_points", _FakeEntryPoints())
    discovered = registry._discover_plugins()
    assert "ghost" not in discovered


def test_discover_plugins_swallows_metadata_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If entry_points() itself raises, discovery returns empty dict."""

    def _boom(*a: Any, **kw: Any) -> Any:
        raise OSError("metadata unreadable")

    monkeypatch.setattr(registry, "entry_points", _boom)
    assert registry._discover_plugins() == {}


# ---------------------------------------------------------------------------
# cli._mask_proxy_url
# ---------------------------------------------------------------------------


def test_mask_proxy_url_redacts_credentials() -> None:
    from webscan.cli import _mask_proxy_url

    # With creds => creds replaced with ***.
    masked = _mask_proxy_url("http://user:secret@proxy.local:8080")
    assert "secret" not in masked
    assert "user" not in masked
    assert "***" in masked
    assert "proxy.local:8080" in masked


def test_mask_proxy_url_passthrough_without_creds() -> None:
    from webscan.cli import _mask_proxy_url

    assert _mask_proxy_url("http://proxy.local:8080") == "http://proxy.local:8080"
    # SOCKS5 with creds => redacted.
    masked = _mask_proxy_url("socks5://u:p@127.0.0.1:9050")
    assert "p" not in masked.replace("127.0.0.1", "")  # 'p' appears in port — check explicitly
    assert "***" in masked
    assert "9050" in masked
