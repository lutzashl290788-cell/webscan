"""Tests for the ssl_tls plugin (network probe is monkeypatched)."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins import ssl_tls
from webscan.plugins.ssl_tls import SslTlsPlugin, _days_until, _parse_cert_time


class _Resp:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _Session:
    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = headers

    def get(self, _url: str, **_kw: object) -> _Resp:
        return _Resp(self._headers)


def test_parse_cert_time_roundtrip() -> None:
    dt = _parse_cert_time("Jun  1 12:00:00 2099 GMT")
    assert dt is not None
    assert dt.year == 2099


def test_days_until_future() -> None:
    days = _days_until("Jun  1 12:00:00 2099 GMT")
    assert days is not None and days > 1000


async def test_http_target_skipped() -> None:
    plugin = SslTlsPlugin()
    session = _Session({})
    findings = await plugin.run("http://example.com", session)  # type: ignore[arg-type]
    assert findings == []


async def test_weak_protocol_and_missing_hsts(monkeypatch: object) -> None:
    # Pretend the server negotiated TLSv1.0 with a valid (far-future) cert.
    monkeypatch.setattr(  # type: ignore[attr-defined]
        ssl_tls,
        "_probe_tls",
        lambda host, port: ("TLSv1", "Jun  1 12:00:00 2099 GMT", False),
    )
    plugin = SslTlsPlugin()
    session = _Session({})  # no HSTS header

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    titles = [f.title for f in findings]
    assert any("Weak TLS protocol" in t for t in titles)
    assert any("Missing HSTS" in t for t in titles)
    weak = next(f for f in findings if "Weak TLS" in f.title)
    assert weak.severity is Severity.HIGH


async def test_expired_certificate(monkeypatch: object) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        ssl_tls,
        "_probe_tls",
        lambda host, port: ("TLSv1.3", "Jun  1 12:00:00 2000 GMT", True),
    )
    plugin = SslTlsPlugin()
    session = _Session({"Strict-Transport-Security": "max-age=31536000"})

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert any("Expired TLS certificate" in f.title for f in findings)
    # HSTS present → no HSTS finding.
    assert not any("Missing HSTS" in f.title for f in findings)
