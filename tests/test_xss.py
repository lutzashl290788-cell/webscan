"""Tests for the reflected XSS plugin."""
from __future__ import annotations

import html as html_lib

from webscan.models import Severity
from webscan.plugins.xss import XssPlugin


class _Resp:
    def __init__(self, body: str) -> None:
        self._body = body

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _ReflectSession:
    """Reflects the raw query value back into the body (vulnerable app)."""

    def __init__(self, *, escape: bool = False) -> None:
        self.escape = escape
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
        return _Resp(f"<html><body>Hello {value}</body></html>")


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
