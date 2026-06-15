"""Plugin: detect open redirects in query parameters."""
from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

# Sentinel host we try to bounce the victim to. A redirect whose Location points
# here proves the parameter controls the destination.
_EVIL = "evil-webscan.example"
_PAYLOADS: list[str] = [
    f"https://{_EVIL}/",
    f"//{_EVIL}/",
    f"https:/{_EVIL}/",
]

# Parameter names commonly used for redirects; others are skipped to limit noise.
_REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "returnurl", "return_url", "dest", "destination", "continue", "goto",
    "target", "rurl", "forward", "callback",
}


class OpenRedirectPlugin(BasePlugin):
    """Probes redirect-like query parameters for open redirect."""

    name = "open_redirect"
    description = "Detect open redirects in URL query parameters"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        for param_name in params:
            if param_name.lower() not in _REDIRECT_PARAMS:
                continue

            for payload in _PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()

                location = await self._redirect_location(session, test_url)
                if location is None or not _points_to_evil(location):
                    continue

                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Open redirect in parameter '{param_name}'",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Parameter '{param_name}' controls the redirect "
                            "destination: a crafted value redirected the response to "
                            "an attacker-controlled host without validation."
                        ),
                        url=test_url,
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "location": location,
                        },
                        remediation=(
                            "Validate redirect targets against an allow-list of "
                            "internal paths or hosts; never redirect to a raw "
                            "user-supplied absolute URL."
                        ),
                    )
                )
                break

        return findings

    async def _redirect_location(
        self, session: aiohttp.ClientSession, url: str
    ) -> str | None:
        try:
            async with session.get(
                url, ssl=False, allow_redirects=False
            ) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    return resp.headers.get("Location")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        return None


def _points_to_evil(location: str) -> bool:
    """True only if *location*'s actual destination host is the sentinel host.

    Checking the parsed host — not a substring — avoids the false positive where
    the sentinel merely appears inside a query string of a same-site redirect,
    e.g. ``Location: /login?next=https://evil-webscan.example/`` (which keeps the
    victim on the original host and is therefore safe).
    """
    host = (urlparse(location).hostname or "").lower()
    return host == _EVIL
