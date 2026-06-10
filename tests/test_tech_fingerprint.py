"""Tests for the technology fingerprint plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.tech_fingerprint import TechFingerprintPlugin


async def test_detects_header_and_body_signatures() -> None:
    response = FakeResponse(
        status=200,
        body='<html><link href="/wp-content/themes/x/style.css"></html>',
        headers=[
            ("Server", "nginx/1.25.1"),
            ("X-Powered-By", "PHP/8.2.0"),
        ],
    )
    session = FakeSession(response)
    plugin = TechFingerprintPlugin()

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.INFO
    techs = finding.evidence["technologies"]
    assert "Nginx" in techs
    assert "PHP" in techs
    assert "WordPress" in techs


async def test_meta_generator_detected() -> None:
    response = FakeResponse(
        status=200,
        body='<meta name="generator" content="Joomla! 4.2">',
        headers=[("Server", "Apache")],
    )
    session = FakeSession(response)
    plugin = TechFingerprintPlugin()

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    techs = findings[0].evidence["technologies"]
    assert "Apache" in techs
    assert any("Joomla" in t for t in techs)


async def test_no_signatures_yields_nothing() -> None:
    response = FakeResponse(status=200, body="<html>plain</html>", headers=[])
    session = FakeSession(response)
    plugin = TechFingerprintPlugin()

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings == []
