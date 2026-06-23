"""Authentication support: cookies, headers, basic-auth and form login.

Produces the headers/cookies the engine attaches to its shared session, and
can perform a form-based login up front to capture a session cookie.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import parse_qsl

import aiohttp

from webscan.engine import _build_redirect_safe_trace


@dataclass
class AuthConfig:
    """User-supplied authentication parameters from the CLI."""

    cookie: str = ""  # raw "k=v; k2=v2" cookie header
    headers: list[str] = field(default_factory=list)  # "Name: Value" strings
    basic_auth: str = ""  # "user:password"
    login_url: str = ""
    login_data: str = ""  # "user=a&pass=b" urlencoded form body

    def is_configured(self) -> bool:
        return bool(
            self.cookie
            or self.headers
            or self.basic_auth
            or (self.login_url and self.login_data)
        )


@dataclass
class PreparedAuth:
    """Resolved auth material ready to attach to a ClientSession."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


def _parse_header_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers[name.strip()] = value.strip()
    return headers


def _parse_cookie_header(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for pair in raw.split(";"):
        name, sep, value = pair.strip().partition("=")
        if sep and name:
            cookies[name] = value
    return cookies


def _basic_auth_header(credentials: str) -> dict[str, str]:
    import base64

    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


async def prepare_auth(
    config: AuthConfig,
    ssl_ctx: object,
    timeout: aiohttp.ClientTimeout,
) -> PreparedAuth:
    """Resolve *config* into concrete headers/cookies.

    Static material (cookie, headers, basic-auth) is parsed directly. When a
    login URL + data are supplied, a one-off POST is performed and any returned
    cookies are captured for the scan session.
    """
    prepared = PreparedAuth()

    prepared.headers.update(_parse_header_lines(config.headers))

    if config.basic_auth:
        prepared.headers.update(_basic_auth_header(config.basic_auth))

    if config.cookie:
        prepared.cookies.update(_parse_cookie_header(config.cookie))

    if config.login_url and config.login_data:
        login_cookies = await _form_login(config, ssl_ctx, timeout)
        prepared.cookies.update(login_cookies)

    return prepared


async def _form_login(
    config: AuthConfig,
    ssl_ctx: object,
    timeout: aiohttp.ClientTimeout,
) -> dict[str, str]:
    data = dict(parse_qsl(config.login_data))
    captured: dict[str, str] = {}

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=aiohttp.TCPConnector(ssl=ssl_ctx),  # type: ignore[arg-type]
        # Strip Authorization / Cookie / X-API-Key / X-Auth-Token /
        # Proxy-Authorization when aiohttp follows a redirect to a different
        # host. Without this, a 307/308 cross-origin redirect would replay
        # the login form (with credentials) on the attacker host.
        trace_configs=[_build_redirect_safe_trace()],
    ) as session:
        try:
            # allow_redirects=False: a login endpoint must not transparently
            # redirect the POST body to a third-party host. If a redirect is
            # expected (e.g. to a dashboard), the operator should follow it
            # manually — the cookies we capture here are still valid.
            async with session.post(
                config.login_url, data=data, ssl=False, allow_redirects=False
            ) as resp:
                await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise LoginError(
                f"Login request to {config.login_url} failed: {exc}"
            ) from exc

        for cookie in session.cookie_jar:
            captured[cookie.key] = cookie.value

    if not captured:
        raise LoginError(
            f"Login to {config.login_url} returned no session cookie. "
            "Check the credentials and field names in --login-data."
        )
    return captured


class LoginError(RuntimeError):
    """Raised when a form-based login cannot establish a session."""
