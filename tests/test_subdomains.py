"""Tests for the subdomain enumeration plugin."""
from __future__ import annotations

import asyncio
import json

import aiohttp
import pytest

from webscan.models import Severity
from webscan.plugins.subdomains import (
    SubdomainsPlugin,
    _is_hostname,
    _registrable_domain,
)

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
    plugin = SubdomainsPlugin(resolve=False, bruteforce=False)
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
    plugin = SubdomainsPlugin(resolve=False, bruteforce=False)
    session = _Session("[]")

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings == []


async def test_non_200_no_finding() -> None:
    plugin = SubdomainsPlugin(resolve=False, bruteforce=False)
    session = _Session("error", status=503)

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings == []


async def test_bruteforce_merges_resolved_hits(monkeypatch: object) -> None:
    # Pretend two brute-forced prefixes resolve; CT returns nothing extra.
    async def fake_resolve(self: object, names: list[str]) -> list[str]:
        return [n for n in names if n in ("www.example.com", "vpn.example.com")]

    monkeypatch.setattr(  # type: ignore[attr-defined]
        SubdomainsPlugin, "_resolve_all", fake_resolve
    )
    plugin = SubdomainsPlugin(resolve=False, bruteforce=True)
    session = _Session("[]")  # empty CT response

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    ev = findings[0].evidence
    assert set(ev["bruteforce_hits"]) == {"www.example.com", "vpn.example.com"}
    assert "www.example.com" in ev["subdomains"]


async def test_no_hostname_returns_empty() -> None:
    plugin = SubdomainsPlugin(resolve=False, bruteforce=False)
    findings = await plugin.run("https://", _Session("[]"))  # type: ignore[arg-type]
    assert findings == []


async def test_resolve_branch_confirms_ct_names(monkeypatch: pytest.MonkeyPatch) -> None:
    # With resolve=True, CT-discovered names are checked against DNS.
    async def fake_resolve(self: object, names: list[str]) -> list[str]:
        return [n for n in names if n == "api.example.com"]

    monkeypatch.setattr(SubdomainsPlugin, "_resolve_all", fake_resolve)
    plugin = SubdomainsPlugin(resolve=True, bruteforce=False)
    session = _Session(_CRT_JSON)

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings[0].evidence["resolved"] == ["api.example.com"]


class _RaisingSession:
    def get(self, _url: str, **_kw: object) -> object:
        raise aiohttp.ClientError("network down")


async def test_crtsh_client_error_returns_no_finding() -> None:
    plugin = SubdomainsPlugin(resolve=False, bruteforce=False)
    findings = await plugin.run("https://example.com", _RaisingSession())  # type: ignore[arg-type]
    assert findings == []


async def test_crtsh_invalid_json_returns_no_finding() -> None:
    plugin = SubdomainsPlugin(resolve=False, bruteforce=False)
    session = _Session("not json at all {{{")
    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]
    assert findings == []


# ── _resolve_all (real implementation, getaddrinfo faked) ────────────────────────

async def test_resolve_all_keeps_only_resolving_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(name: str, _port: object) -> list[object]:
        if name == "good.example.com":
            return [("ok",)]
        raise OSError("NXDOMAIN")

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    plugin = SubdomainsPlugin()

    out = await plugin._resolve_all(["good.example.com", "bad.example.com"])

    assert out == ["good.example.com"]


async def test_resolve_all_empty_list_short_circuits() -> None:
    assert await SubdomainsPlugin()._resolve_all([]) == []


# ── _is_hostname ──────────────────────────────────────────────────────────────────

def test_is_hostname_validation() -> None:
    assert _is_hostname("api.example.com") is True
    assert _is_hostname("") is False
    assert _is_hostname("has space.example.com") is False
    assert _is_hostname("a" * 300) is False  # too long overall
    assert _is_hostname("a." + "b" * 64 + ".com") is False  # label too long
