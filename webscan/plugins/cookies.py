"""Plugin: audit Set-Cookie security attributes."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin


class CookiesPlugin(BasePlugin):
    """Checks Set-Cookie headers for missing Secure / HttpOnly / SameSite flags."""

    name = "cookies"
    description = "Audit cookie security flags (Secure, HttpOnly, SameSite)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                raw_cookies = resp.headers.getall("Set-Cookie", [])
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        for raw in raw_cookies:
            findings.extend(self._check_cookie(raw, target))
        return findings

    def _check_cookie(self, raw: str, target: str) -> list[Finding]:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            return []

        name = parts[0].split("=", 1)[0].strip() or "cookie"
        flags: set[str] = set()
        attrs: dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                attrs[key.strip().lower()] = value.strip()
            else:
                flags.add(part.lower())

        has_secure = "secure" in flags
        has_httponly = "httponly" in flags
        samesite = attrs.get("samesite", "").lower()

        findings: list[Finding] = []

        def add(title: str, severity: Severity, description: str, remediation: str) -> None:
            findings.append(
                Finding(
                    plugin=self.name,
                    title=title,
                    severity=severity,
                    description=description,
                    url=target,
                    evidence={"cookie": name, "set_cookie": raw},
                    remediation=remediation,
                )
            )

        if not has_secure:
            add(
                f"Cookie '{name}' missing Secure flag",
                Severity.MEDIUM,
                f"Cookie '{name}' is set without the Secure attribute, so it may be "
                "transmitted over plain HTTP and intercepted.",
                "Add the Secure attribute so the cookie is only sent over HTTPS.",
            )
        if not has_httponly:
            add(
                f"Cookie '{name}' missing HttpOnly flag",
                Severity.MEDIUM,
                f"Cookie '{name}' is accessible to JavaScript (no HttpOnly), making it "
                "stealable via cross-site scripting.",
                "Add the HttpOnly attribute unless client-side scripts must read it.",
            )
        if not samesite:
            add(
                f"Cookie '{name}' missing SameSite attribute",
                Severity.LOW,
                f"Cookie '{name}' has no SameSite attribute and may be sent on "
                "cross-site requests, enabling CSRF.",
                "Set SameSite=Lax or SameSite=Strict as appropriate.",
            )
        elif samesite == "none" and not has_secure:
            add(
                f"Cookie '{name}' uses SameSite=None without Secure",
                Severity.MEDIUM,
                f"Cookie '{name}' declares SameSite=None but lacks Secure; browsers "
                "reject this combination, so cross-site behaviour is undefined.",
                "SameSite=None must always be paired with the Secure attribute.",
            )

        return findings
