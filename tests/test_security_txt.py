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


# ----------------------------------------------------------------------
# Coverage gaps
# ----------------------------------------------------------------------

import aiohttp  # noqa: E402


class _ClientError(Exception):
    pass


class _RaisingResp:
    async def __aenter__(self) -> _RaisingResp:
        raise _ClientError("connection reset")

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return ""


async def test_network_error_returns_empty() -> None:
    """Lines 69-70: a ClientError fetching security.txt yields no findings."""
    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        plugin = SecurityTxtPlugin()

        class _BoomSession:
            def get(self, _url: str, **_kw: object) -> _RaisingResp:
                return _RaisingResp()

        findings = await plugin.run(
            "https://example.com", _BoomSession()  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_malformed_lines_ignored_and_all_optional_fields_present() -> None:
    """Lines 86/88: comment/colon-less lines are ignored; optional fields tracked.

    Exercises the ``line.startswith("#")`` and ``":" not in line`` skips, plus
    the Acknowledgments / Hiring branches so they are counted in the summary.
    """
    body = (
        "# This is a comment line\n"
        "   \n"  # blank line
        "garbled line with no colon\n"
        "Contact: mailto:security@example.com\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Encryption: https://example.com/pgp-key.txt\n"
        "Acknowledgments: https://example.com/thanks\n"
        "Hiring: https://example.com/jobs\n"
        "Preferred-Languages: en\n"
    )
    session = FakeSession(FakeResponse(status=200, body=body))
    findings = await SecurityTxtPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    present = next(f for f in findings if f.title == "security.txt: present")
    fields = present.evidence["fields"]
    # All six recognised fields should be present, proving the optional branches
    # (encryption/acknowledgments/hiring/preferred-languages) were walked.
    assert "Contact" in fields
    assert "Expires" in fields
    assert "Encryption" in fields
    assert "Acknowledgments" in fields
    assert "Hiring" in fields
    assert "Preferred-Languages" in fields


async def test_present_with_neither_contact_nor_expires() -> None:
    """Lines 120/122: missing both Contact and Expires flags both findings."""
    body = "Hiring: https://example.com/jobs\n"
    session = FakeSession(FakeResponse(status=200, body=body))
    findings = await SecurityTxtPlugin().run("https://example.com", session)  # type: ignore[arg-type]

    titles = {f.title for f in findings}
    assert "security.txt: missing Contact field" in titles
    assert "security.txt: missing Expires field" in titles
