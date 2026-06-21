"""Plugin: analyse robots.txt and sitemap.xml for hygiene and info leaks.

Two practical, beginner-friendly checks:

1. Site owners often list sensitive paths under ``Disallow:`` in robots.txt
   (e.g. ``/admin``, ``/backup``) — which publicly *advertises* exactly what
   they wanted to hide. We surface those as an information-disclosure finding.
2. A missing sitemap.xml is reported as a low-severity hygiene note.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# Disallowed paths whose names suggest something sensitive worth flagging.
_SENSITIVE = re.compile(
    r"(admin|backup|secret|private|config|\.git|\.env|db|database|sql|"
    r"login|dashboard|panel|internal|staging|test|tmp|old|api|upload)",
    re.IGNORECASE,
)


class RobotsSitemapPlugin(BasePlugin):
    """Inspects robots.txt and sitemap.xml for leaks and basic hygiene."""

    name = "robots_sitemap"
    description = "Analyse robots.txt / sitemap.xml for info leaks and hygiene"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[Finding] = []

        robots = await self._get(session, f"{base}/robots.txt")
        if robots is not None:
            findings.extend(self._analyse_robots(robots, base))

        sitemap = await self._get(session, f"{base}/sitemap.xml")
        if sitemap is None:
            findings.append(
                Finding(
                    plugin=self.name,
                    title="No sitemap.xml found",
                    severity=Severity.LOW,
                    description=(
                        "No sitemap.xml was served. A sitemap helps search engines "
                        "and is a sign of good site hygiene (informational)."
                    ),
                    url=f"{base}/sitemap.xml",
                    evidence={},
                    remediation="Publish a sitemap.xml listing your public URLs.",
                )
            )

        return findings

    def _analyse_robots(self, body: str, base: str) -> list[Finding]:
        disallowed = [
            line.split(":", 1)[1].strip()
            for line in body.splitlines()
            if line.strip().lower().startswith("disallow:")
            and ":" in line
        ]
        sensitive = sorted({p for p in disallowed if p and _SENSITIVE.search(p)})
        if not sensitive:
            return []

        return [
            Finding(
                plugin=self.name,
                title=f"robots.txt discloses {len(sensitive)} sensitive path(s)",
                severity=Severity.LOW,
                description=(
                    "robots.txt lists sensitive-looking paths under Disallow. "
                    "robots.txt is public, so this advertises locations you may "
                    "have intended to keep private."
                ),
                url=f"{base}/robots.txt",
                evidence={"disallowed_sensitive": sensitive[:50]},
                remediation=(
                    "Don't rely on robots.txt to hide sensitive paths — it is "
                    "public. Protect them with authentication/authorisation and "
                    "remove revealing entries."
                ),
            )
        ]

    async def _get(self, session: aiohttp.ClientSession, url: str) -> str | None:
        try:
            async with session.get(url, ssl=False) as resp:
                if resp.status != 200:
                    return None
                return await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None
