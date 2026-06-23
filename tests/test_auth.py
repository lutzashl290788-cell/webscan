"""Tests for the authentication helpers."""
from __future__ import annotations

import base64
import ssl

import aiohttp
import pytest

from webscan import auth as auth_mod
from webscan.auth import AuthConfig, LoginError, prepare_auth

_TIMEOUT = aiohttp.ClientTimeout(total=5)
_SSL_CTX = ssl.create_default_context()


class _Cookie:
    def __init__(self, key: str, value: str) -> None:
        self.key = key
        self.value = value


class _LoginResp:
    async def __aenter__(self) -> _LoginResp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def read(self) -> bytes:
        return b""


class _LoginSession:
    """Fake ClientSession that records the POST and exposes a cookie jar."""

    def __init__(self, cookies: list[_Cookie], *, raise_on_post: bool = False) -> None:
        self.cookie_jar = cookies
        self._raise = raise_on_post
        self.posted: tuple[str, dict[str, object]] | None = None

    async def __aenter__(self) -> _LoginSession:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    def post(self, url: str, **kwargs: object) -> _LoginResp:
        if self._raise:
            raise aiohttp.ClientError("connection refused")
        self.posted = (url, kwargs)
        return _LoginResp()


async def test_static_cookie_and_headers() -> None:
    config = AuthConfig(
        cookie="session=abc123; theme=dark",
        headers=["Authorization: Bearer TOK", "X-Api-Key: k1"],
    )

    prepared = await prepare_auth(config, object(), _TIMEOUT)

    assert prepared.cookies == {"session": "abc123", "theme": "dark"}
    assert prepared.headers["Authorization"] == "Bearer TOK"
    assert prepared.headers["X-Api-Key"] == "k1"


async def test_basic_auth_encodes_credentials() -> None:
    config = AuthConfig(basic_auth="admin:secret")

    prepared = await prepare_auth(config, object(), _TIMEOUT)

    expected = base64.b64encode(b"admin:secret").decode()
    assert prepared.headers["Authorization"] == f"Basic {expected}"


async def test_is_configured_flag() -> None:
    assert AuthConfig().is_configured() is False
    assert AuthConfig(cookie="a=b").is_configured() is True
    assert AuthConfig(login_url="x").is_configured() is False  # needs data too
    assert AuthConfig(login_url="x", login_data="u=a").is_configured() is True


async def test_malformed_header_lines_ignored() -> None:
    config = AuthConfig(headers=["no-colon-here", "Good: yes"])

    prepared = await prepare_auth(config, object(), _TIMEOUT)

    assert prepared.headers == {"Good": "yes"}


# ── form login ──────────────────────────────────────────────────────────────────

async def test_form_login_captures_session_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LoginSession([_Cookie("session", "xyz789")])
    monkeypatch.setattr(auth_mod.aiohttp, "ClientSession", lambda **_kw: session)

    config = AuthConfig(login_url="https://t.test/login", login_data="user=a&pass=b")
    prepared = await prepare_auth(config, _SSL_CTX, _TIMEOUT)

    assert prepared.cookies == {"session": "xyz789"}
    # The form body was URL-decoded into a dict before posting.
    assert session.posted is not None
    assert session.posted[0] == "https://t.test/login"
    assert session.posted[1]["data"] == {"user": "a", "pass": "b"}


async def test_form_login_no_cookie_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LoginSession([])  # server set no cookies
    monkeypatch.setattr(auth_mod.aiohttp, "ClientSession", lambda **_kw: session)

    config = AuthConfig(login_url="https://t.test/login", login_data="user=a")
    with pytest.raises(LoginError, match="no session cookie"):
        await prepare_auth(config, _SSL_CTX, _TIMEOUT)


async def test_form_login_request_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _LoginSession([], raise_on_post=True)
    monkeypatch.setattr(auth_mod.aiohttp, "ClientSession", lambda **_kw: session)

    config = AuthConfig(login_url="https://t.test/login", login_data="user=a")
    with pytest.raises(LoginError, match="failed"):
        await prepare_auth(config, _SSL_CTX, _TIMEOUT)
