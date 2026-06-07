"""Plugin: detect CORS (Cross-Origin Resource Sharing) misconfigurations."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

# Distinctive origin sent to see whether the server blindly reflects it.
PROBE_ORIGIN = "https://webscan-probe.example"


class CorsPlugin(BasePlugin):
    """Inspects Access-Control-* response headers for unsafe CORS policies."""

    name = "cors"
    description = "Detect permissive or reflected CORS configurations"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(
                target,
                headers={"Origin": PROBE_ORIGIN},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        with_creds = acac.strip().lower() == "true"
        evidence = {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "sent_origin": PROBE_ORIGIN,
        }

        if acao == PROBE_ORIGIN:
            credentials_note = (
                " together with Access-Control-Allow-Credentials: true, letting any "
                "site read authenticated responses."
                if with_creds
                else ", letting any site read the response."
            )
            findings.append(
                Finding(
                    plugin=self.name,
                    title="CORS reflects an arbitrary Origin",
                    severity=Severity.HIGH if with_creds else Severity.MEDIUM,
                    description=(
                        "The server reflected the request's Origin header back in "
                        "Access-Control-Allow-Origin" + credentials_note
                    ),
                    url=target,
                    evidence=evidence,
                    remediation=(
                        "Validate the Origin against an explicit allow-list; never "
                        "reflect arbitrary origins, especially with credentials enabled."
                    ),
                )
            )
        elif acao == "*":
            wildcard_note = (
                " while credentials are allowed, which is invalid per spec and unsafe."
                if with_creds
                else ". Acceptable for fully public data, but verify the endpoint "
                "exposes nothing sensitive."
            )
            findings.append(
                Finding(
                    plugin=self.name,
                    title="CORS allows any origin (*)",
                    severity=Severity.HIGH if with_creds else Severity.LOW,
                    description=(
                        "Access-Control-Allow-Origin is the wildcard '*'" + wildcard_note
                    ),
                    url=target,
                    evidence=evidence,
                    remediation=(
                        "Restrict Access-Control-Allow-Origin to specific trusted "
                        "origins instead of '*'."
                    ),
                )
            )

        return findings
