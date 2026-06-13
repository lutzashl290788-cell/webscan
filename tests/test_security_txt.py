"""Tests for the security.txt (RFC 9116) plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.security_txt import SecurityTxtPlugin


async def test_absent_security_txt_is_info() -> None:
    session = FakeSession(FakeResponse(status=404))
    findings = await SecurityTxtPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].title == "security.txt not found"
    assert findings[0].severity is Severity.INFO


async def test_present_with_contact_and_expires() -> None:
    body = (
        "Contact: mailto:security@example.com\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Preferred-Languages: en\n"
    )
    session = FakeSession(FakeResponse(status=200, body=body))
    findings = await SecurityTxtPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    titles = {f.title for f in findings}
    assert "security.txt: Contact" in titles
    assert "security.txt: Expires" in titles
    assert "security.txt: present" in titles
    # A complete file should not raise the "missing Contact" finding.
    assert "security.txt: missing Contact field" not in titles


async def test_present_without_contact_flags_medium() -> None:
    body = "Encryption: https://example.com/pgp-key.txt\n"
    session = FakeSession(FakeResponse(status=200, body=body))
    findings = await SecurityTxtPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    missing = next(f for f in findings if f.title == "security.txt: missing Contact field")
    assert missing.severity is Severity.MEDIUM
