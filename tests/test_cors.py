"""Tests for the cors plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.cors import PROBE_ORIGIN, CorsPlugin

_TARGET = "https://example.com"


async def test_reflected_origin_with_credentials_is_high() -> None:
    plugin = CorsPlugin()
    resp = FakeResponse(
        headers=[
            ("Access-Control-Allow-Origin", PROBE_ORIGIN),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    )
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "reflects" in findings[0].title.lower()


async def test_wildcard_without_credentials_is_low() -> None:
    plugin = CorsPlugin()
    resp = FakeResponse(headers=[("Access-Control-Allow-Origin", "*")])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


async def test_no_cors_headers_yields_nothing() -> None:
    plugin = CorsPlugin()
    resp = FakeResponse(headers=[("Content-Type", "text/html")])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert findings == []
