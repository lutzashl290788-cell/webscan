"""Tests for the security-headers plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.headers import HeadersPlugin


async def test_flags_missing_headers() -> None:
    session = FakeSession(FakeResponse(status=200, headers=[]))
    findings = await HeadersPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    titles = {f.title for f in findings}
    assert "Missing header: Content-Security-Policy" in titles
    assert "Missing header: Strict-Transport-Security" in titles
    # CSP / HSTS are HIGH severity.
    csp = next(f for f in findings if "Content-Security-Policy" in f.title)
    assert csp.severity is Severity.HIGH


async def test_flags_information_disclosure() -> None:
    session = FakeSession(FakeResponse(status=200, headers=[("Server", "nginx/1.25")]))
    findings = await HeadersPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    disclosure = [f for f in findings if f.title.startswith("Information disclosure")]
    assert any(f.evidence.get("value") == "nginx/1.25" for f in disclosure)


async def test_flags_weak_csp() -> None:
    headers = [
        ("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'"),
        ("Strict-Transport-Security", "max-age=1"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
    ]
    session = FakeSession(FakeResponse(status=200, headers=headers))
    findings = await HeadersPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    assert any("Weak CSP directive" in f.title for f in findings)


async def test_skips_static_assets() -> None:
    """Do not repeat document security findings for JS/CSS/image assets."""
    session = FakeSession(FakeResponse(
        status=200,
        headers=[("Content-Type", "application/javascript")],
    ))
    findings = await HeadersPlugin().run("https://example.com/assets/app.js", session)  # type: ignore[arg-type]
    assert findings == []
