"""Tests for the cookies plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.plugins.cookies import CookiesPlugin

_TARGET = "https://example.com"


async def test_insecure_cookie_flags_all_three() -> None:
    plugin = CookiesPlugin()
    resp = FakeResponse(headers=[("Set-Cookie", "sid=abc123; Path=/")])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    titles = " ".join(f.title for f in findings)
    assert "Secure" in titles
    assert "HttpOnly" in titles
    assert "SameSite" in titles
    assert len(findings) == 3


async def test_hardened_cookie_has_no_findings() -> None:
    plugin = CookiesPlugin()
    resp = FakeResponse(
        headers=[("Set-Cookie", "sid=abc123; Secure; HttpOnly; SameSite=Strict")],
    )
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert findings == []


async def test_samesite_none_without_secure_is_reported() -> None:
    plugin = CookiesPlugin()
    resp = FakeResponse(headers=[("Set-Cookie", "sid=abc; HttpOnly; SameSite=None")])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    titles = " ".join(f.title for f in findings)
    assert "Secure" in titles
    assert "SameSite=None without Secure" in titles
