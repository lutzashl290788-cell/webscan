"""Plugin: detect dangerous HTTP methods advertised by the target."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

# Method -> (severity, why it is risky)
_DANGEROUS_METHODS: dict[str, tuple[Severity, str]] = {
    "PUT": (Severity.HIGH, "allows clients to upload or overwrite files on the server"),
    "DELETE": (Severity.HIGH, "allows clients to delete resources on the server"),
    "TRACE": (Severity.MEDIUM, "enables Cross-Site Tracing (XST) attacks"),
    "CONNECT": (Severity.MEDIUM, "can let the server be abused as an open proxy"),
    "PATCH": (Severity.LOW, "allows partial modification of server resources"),
}


class HttpMethodsPlugin(BasePlugin):
    """Sends OPTIONS and flags any dangerous methods listed in the Allow header."""

    name = "http_methods"
    description = "Detect dangerous enabled HTTP methods (PUT, DELETE, TRACE, ...)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.options(
                target,
                allow_redirects=False,
                ssl=False,
            ) as resp:
                allow = resp.headers.get("Allow", "")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        if not allow:
            return findings

        advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}

        for method, (severity, note) in _DANGEROUS_METHODS.items():
            if method not in advertised:
                continue
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Dangerous HTTP method enabled: {method}",
                    severity=severity,
                    description=(
                        f"The server advertises the {method} method in its Allow "
                        f"header, which {note}."
                    ),
                    url=target,
                    evidence={"allow": allow, "method": method},
                    remediation=(
                        f"Disable the {method} method at the web server or framework "
                        "level unless it is explicitly required."
                    ),
                )
            )

        return findings
