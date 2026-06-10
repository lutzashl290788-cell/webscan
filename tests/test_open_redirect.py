"""Tests for the open redirect plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.open_redirect import OpenRedirectPlugin


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
