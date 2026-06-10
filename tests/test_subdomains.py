"""Tests for the subdomain enumeration plugin."""
from __future__ import annotations

import json

from webscan.models import Severity
from webscan.plugins.subdomains import SubdomainsPlugin, _registrable_domain

_CRT_JSON = json.dumps(
    [
        {"name_value": "www.example.com"},
        {"name_value": "api.example.com\nstaging.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "example.com"},  # apex, excluded
        {"name_value": "mail.other.com"},  # different domain, excluded
    ]
)


class _Resp:
    def __init__(self, body: str, status: int = 200) -> None:
        self._body = body
        self.status = status

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _Session:
    def __init__(self, body: str, status: int = 200) -> None:
        self._body = body
        self._status = status
        self.calls = 0

    def get(self, _url: str, **_kw: object) -> _Resp:
        self.calls += 1
        return _Resp(self._body, self._status)


async def test_registrable_domain() -> None:
    assert _registrable_domain("a.b.example.com") == "example.com"
    assert _registrable_domain("example.com") == "example.com"
    assert _registrable_domain("localhost") == "localhost"


async def test_discovers_and_dedupes_subdomains() -> None:
    plugin = SubdomainsPlugin(resolve=False)
    session = _Session(_CRT_JSON)

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.INFO
    subs = finding.evidence["subdomains"]
    assert "www.example.com" in subs
    assert "api.example.com" in subs
    assert "staging.example.com" in subs
    assert "example.com" not in subs       # apex excluded
    assert all("other.com" not in s for s in subs)  # foreign domain excluded


async def test_empty_crtsh_no_finding() -> None:
    plugin = SubdomainsPlugin(resolve=False)
    session = _Session("[]")

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings == []


async def test_non_200_no_finding() -> None:
    plugin = SubdomainsPlugin(resolve=False)
    session = _Session("error", status=503)

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings == []
