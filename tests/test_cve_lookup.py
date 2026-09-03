"""Tests for the CVE lookup plugin (cve.org / NVD)."""
from __future__ import annotations

import json

from tests._fakes import FakeHeaders
from webscan.models import Severity
from webscan.plugins.cve_lookup import (
    CveLookupPlugin,
    _cve_severity,
    _english_description,
    _year_from_id,
)
from webscan.retry import RetryConfig

_NO_RETRY = RetryConfig(retries=0, base_delay=0.0)

_NVD_PAYLOAD = json.dumps({
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-23017",
                "descriptions": [
                    {"lang": "en", "value": "A security issue in nginx resolver."},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}],
                },
            }
        }
    ]
})


class _Resp:
    def __init__(self, status: int = 200, body: str = "", headers: object = None) -> None:
        self.status = status
        self._body = body
        self.headers = headers if headers is not None else FakeHeaders([])

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _Session:
    """Serves a banner page and a canned NVD response by URL."""

    def __init__(self, server_header: str, nvd_body: str) -> None:
        self._server = server_header
        self._nvd = nvd_body

    def get(self, url: str, **_kw: object) -> _Resp:
        if url.startswith("https://services.nvd.nist.gov"):
            return _Resp(200, self._nvd)
        headers = FakeHeaders([("Server", self._server)] if self._server else [])
        return _Resp(200, "", headers)


# ── helpers ───────────────────────────────────────────────────────────────────

def test_year_from_id() -> None:
    assert _year_from_id("CVE-2021-23017") == "2021"
    assert _year_from_id("garbage") == "unknown"


def test_cve_severity_maps_cvss() -> None:
    cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}}
    assert _cve_severity(cve) is Severity.CRITICAL
    assert _cve_severity({}) is Severity.MEDIUM  # default when unknown


def test_english_description_truncates() -> None:
    long = "x" * 500
    cve = {"descriptions": [{"lang": "en", "value": long}]}
    out = _english_description(cve)
    assert out.endswith("…") and len(out) <= 241


# ── end-to-end ────────────────────────────────────────────────────────────────

async def test_maps_banner_version_to_cve() -> None:
    session = _Session("nginx/1.1.1", _NVD_PAYLOAD)
    findings = await CveLookupPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["cve_id"] == "CVE-2021-23017"
    assert f.evidence["year"] == "2021"
    assert "cve.org" in f.evidence["reference"]
    assert f.severity is Severity.HIGH
    assert "nginx" in f.evidence["product"]


async def test_no_banner_no_findings() -> None:
    session = _Session("", _NVD_PAYLOAD)
    findings = await CveLookupPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )
    assert findings == []


# ----------------------------------------------------------------------
# Coverage gaps — resilience branches
# ----------------------------------------------------------------------

import aiohttp  # noqa: E402


class _ClientError(Exception):
    pass


class _RaisingResp:
    async def __aenter__(self) -> _RaisingResp:
        raise _ClientError("network down")

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return ""


async def test_detect_products_network_error_returns_empty() -> None:
    """Lines 74-75: a ClientError on the banner GET yields no products."""

    class _BoomSession:
        def get(self, _url: str, **_kw: object) -> _RaisingResp:
            return _RaisingResp()

    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        plugin = CveLookupPlugin(retry=_NO_RETRY)
        findings = await plugin.run(
            "https://example.com", _BoomSession()  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


class _BadNvdSession:
    """Serves a banner, but returns the given (bad) NVD response."""

    def __init__(self, nvd_status: int, nvd_body: str) -> None:
        self._status = nvd_status
        self._body = nvd_body

    def get(self, url: str, **_kw: object) -> _Resp:
        if url.startswith("https://services.nvd.nist.gov"):
            return _Resp(self._status, self._body)
        return _Resp(200, "", FakeHeaders([("Server", "nginx/1.1.1")]))


async def test_nvd_non_200_returns_empty() -> None:
    """Line 102: a non-200 NVD response yields no findings."""
    session = _BadNvdSession(nvd_status=503, nvd_body="")
    findings = await CveLookupPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )
    assert findings == []


async def test_nvd_invalid_json_returns_empty() -> None:
    """Lines 105-106: malformed JSON from NVD yields no findings."""
    session = _BadNvdSession(nvd_status=200, nvd_body="not-json{")
    findings = await CveLookupPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )
    assert findings == []


def test_english_description_fallback_when_no_english() -> None:
    """Line 155: no English description → fallback string."""
    cve = {"descriptions": [{"lang": "ja", "value": "日本語"}]}
    out = _english_description(cve)
    assert out == "See the CVE record for details."


def test_english_description_fallback_when_not_list() -> None:
    """Line 155: descriptions present but not a list → fallback string."""
    cve = {"descriptions": "unexpected"}
    assert _english_description(cve) == "See the CVE record for details."
