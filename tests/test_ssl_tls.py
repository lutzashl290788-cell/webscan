"""Tests for the ssl_tls plugin (network probe is monkeypatched)."""
from __future__ import annotations

import socket
import ssl

import pytest

from webscan.models import Severity
from webscan.plugins import ssl_tls
from webscan.plugins.ssl_tls import SslTlsPlugin, _days_until, _parse_cert_time, _probe_tls


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


def test_parse_cert_time_invalid_returns_none() -> None:
    assert _parse_cert_time("not a date") is None


def test_days_until_future() -> None:
    days = _days_until("Jun  1 12:00:00 2099 GMT")
    assert days is not None and days > 1000


def test_days_until_unparseable_returns_none() -> None:
    assert _days_until("garbage") is None


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


async def test_no_hostname_returns_empty() -> None:
    plugin = SslTlsPlugin()
    # https scheme but no host (e.g. a bare scheme) → nothing to probe.
    findings = await plugin.run("https://", _Session({}))  # type: ignore[arg-type]
    assert findings == []


async def test_probe_error_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(host: str, port: int) -> object:
        raise OSError("connection refused")

    monkeypatch.setattr(ssl_tls, "_probe_tls", _boom)
    findings = await SslTlsPlugin().run("https://example.com", _Session({}))  # type: ignore[arg-type]
    assert findings == []


async def test_probe_none_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssl_tls, "_probe_tls", lambda host, port: None)
    findings = await SslTlsPlugin().run("https://example.com", _Session({}))  # type: ignore[arg-type]
    assert findings == []


async def test_certificate_expiring_soon_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    # A modern protocol with a cert that is valid but expires within the window.
    soon = _parse_cert_time("Jun  1 12:00:00 2099 GMT")
    assert soon is not None
    monkeypatch.setattr(ssl_tls, "_probe_tls", lambda host, port: ("TLSv1.3", "x", False))
    monkeypatch.setattr(ssl_tls, "_days_until", lambda not_after: 10)

    findings = await SslTlsPlugin().run(
        "https://example.com",
        _Session({"Strict-Transport-Security": "max-age=1"}),  # type: ignore[arg-type]
    )

    warn = next(f for f in findings if "expires in" in f.title)
    assert warn.severity is Severity.MEDIUM
    assert warn.evidence["days_left"] == 10


class _ErrSession:
    """A session whose .get raises, exercising the HSTS error path."""

    def get(self, _url: str, **_kw: object) -> object:
        import aiohttp

        raise aiohttp.ClientError("boom")


async def test_hsts_request_error_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssl_tls, "_probe_tls", lambda host, port: ("TLSv1.3", None, False))
    findings = await SslTlsPlugin().run("https://example.com", _ErrSession())  # type: ignore[arg-type]
    # Probe is clean and HSTS check errored → no findings at all.
    assert findings == []


# ── _probe_tls with a faked socket/ssl stack ────────────────────────────────────

class _FakeSSLSock:
    def __init__(self, version: str, cert: dict[str, object] | None) -> None:
        self._version = version
        self._cert = cert

    def __enter__(self) -> _FakeSSLSock:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def version(self) -> str:
        return self._version

    def getpeercert(self) -> dict[str, object] | None:
        return self._cert


class _FakeCtx:
    def __init__(self, sslsock: _FakeSSLSock) -> None:
        self._sslsock = sslsock
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED

    def wrap_socket(self, sock: object, server_hostname: str) -> _FakeSSLSock:
        return self._sslsock


class _FakeRawSock:
    def __enter__(self) -> _FakeRawSock:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def test_probe_tls_reads_protocol_and_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    sslsock = _FakeSSLSock("TLSv1.3", {"notAfter": "Jun  1 12:00:00 2000 GMT"})
    monkeypatch.setattr(ssl, "create_default_context", lambda: _FakeCtx(sslsock))
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: _FakeRawSock())

    protocol, not_after, expired = _probe_tls("example.com", 443)

    assert protocol == "TLSv1.3"
    assert not_after == "Jun  1 12:00:00 2000 GMT"
    assert expired is True  # year 2000 is in the past


def test_probe_tls_no_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    sslsock = _FakeSSLSock("TLSv1.2", None)
    monkeypatch.setattr(ssl, "create_default_context", lambda: _FakeCtx(sslsock))
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: _FakeRawSock())

    protocol, not_after, expired = _probe_tls("example.com", 443)

    assert protocol == "TLSv1.2"
    assert not_after is None
    assert expired is False
