"""Tests for the reflected XSS plugin."""
from __future__ import annotations

import html as html_lib

from webscan.models import Severity
from webscan.plugins.xss import XssPlugin


class _Resp:
    def __init__(self, body: str, ctype: str = "text/html; charset=utf-8") -> None:
        self._body = body
        self.headers = {"Content-Type": ctype}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _ReflectSession:
    """Reflects the raw query value back into the body (vulnerable app)."""

    def __init__(self, *, escape: bool = False, ctype: str = "text/html") -> None:
        self.escape = escape
        self.ctype = ctype
        self.calls = 0

    def get(self, url: str, **_kw: object) -> _Resp:
        self.calls += 1
        from urllib.parse import parse_qs, urlparse

        value = ""
        qs = parse_qs(urlparse(url).query)
        for vals in qs.values():
            value = vals[0]
        if self.escape:
            value = html_lib.escape(value, quote=True)
        return _Resp(f"<html><body>Hello {value}</body></html>", ctype=self.ctype)


async def test_detects_reflected_payload() -> None:
    plugin = XssPlugin()
    session = _ReflectSession(escape=False)

    findings = await plugin.run("https://example.com/?q=hi", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["parameter"] == "q"


async def test_escaped_reflection_is_not_flagged() -> None:
    plugin = XssPlugin()
    session = _ReflectSession(escape=True)

    findings = await plugin.run("https://example.com/?q=hi", session)  # type: ignore[arg-type]

    assert findings == []


async def test_no_query_params_skips() -> None:
    plugin = XssPlugin()
    session = _ReflectSession()

    findings = await plugin.run("https://example.com/", session)  # type: ignore[arg-type]

    assert findings == []
    assert session.calls == 0


# ----------------------------------------------------------------------
# Coverage gaps — error/edge branches
# ----------------------------------------------------------------------

import aiohttp  # noqa: E402

from webscan.plugins import xss as xss_mod  # noqa: E402


async def test_non_html_content_type_skipped() -> None:
    """A reflection inside JSON/plain-text is inert — not flagged (line 64)."""
    plugin = XssPlugin()
    session = _ReflectSession(escape=False, ctype="application/json")

    findings = await plugin.run("https://example.com/?q=hi", session)  # type: ignore[arg-type]

    assert findings == []


async def test_network_error_during_probe_skipped() -> None:
    """A transport error mid-probe is swallowed, yielding no finding (line 57-58)."""

    class _BoomResp:
        async def __aenter__(self) -> _BoomResp:
            raise _ClientError("boom")

        async def __aexit__(self, *_exc: object) -> bool:
            return False

    class _ClientError(Exception):
        pass

    class _BoomSession:
        def get(self, _url: str, **_kw: object) -> _BoomResp:
            return _BoomResp()

    orig = aiohttp.ClientError
    try:
        aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
        plugin = XssPlugin()
        findings = await plugin.run(
            "https://example.com/?q=hi", _BoomSession()  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_marker_only_payload_no_escape_skipped() -> None:
    """A probe carrying no HTML-special char is skipped as noise (line 71).

    The shipped probes all carry active chars, so we monkeypatch in a plain
    marker to exercise the `payload == html_lib.escape(payload)` guard.
    """
    orig_probes = xss_mod._PROBES
    try:
        xss_mod._PROBES = [("plain", xss_mod._MARKER)]
        plugin = XssPlugin()
        session = _ReflectSession(escape=False)
        findings = await plugin.run(
            "https://example.com/?q=hi", session  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        xss_mod._PROBES = orig_probes


async def test_has_unescaped_reflection_false_when_no_active_chars() -> None:
    """_has_unescaped_reflection returns False for a payload with no active chars."""
    assert xss_mod._has_unescaped_reflection("body wsx9z7 end", "wsx9z7") is False


def test_has_unescaped_reflection_true_when_raw_active_char() -> None:
    """A reflection with a raw active char (not preceded by '&') is flagged."""
    # payload "'x" carries the active char "'", present raw in the body.
    assert xss_mod._has_unescaped_reflection("hello 'x world", "'x") is True


def test_has_unescaped_reflection_false_when_all_entity_tails() -> None:
    """Every reflection sits right after '&' (entity tail) → inert (lines 129-130).

    The payload "'x" carries the active char "'"; it appears in the body but
    each occurrence is preceded by '&' within the 6-char window, so the guard
    treats it as an entity tail and returns False.
    """
    assert xss_mod._has_unescaped_reflection("&&&&&&'xrest", "'x") is False
