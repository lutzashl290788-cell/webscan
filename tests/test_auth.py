"""Tests for the authentication helpers."""
from __future__ import annotations

import base64

import aiohttp

from webscan.auth import AuthConfig, prepare_auth

_TIMEOUT = aiohttp.ClientTimeout(total=5)


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
