"""Plugin: enumerate subdomains via Certificate Transparency (crt.sh)."""
from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

_CRT_SH = "https://crt.sh/?q=%.{domain}&output=json"
_MAX_REPORTED = 200


class SubdomainsPlugin(BasePlugin):
    """Discovers subdomains of the target's registrable domain via CT logs."""

    name = "subdomains"
    description = "Enumerate subdomains via Certificate Transparency (crt.sh)"

    def __init__(self, resolve: bool = True) -> None:
        self._resolve = resolve

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        host = urlparse(target).hostname
        if not host:
            return []

        domain = _registrable_domain(host)
        names = await self._query_crtsh(session, domain)
        if not names:
            return []

        # Confirm which discovered names currently resolve in DNS.
        resolved = await self._resolve_all(sorted(names)) if self._resolve else []

        reported = sorted(names)[:_MAX_REPORTED]
        return [
            Finding(
                plugin=self.name,
                title=f"{len(names)} subdomain(s) discovered for {domain}",
                severity=Severity.INFO,
                description=(
                    f"Certificate Transparency logs (crt.sh) disclosed "
                    f"{len(names)} subdomain(s) of '{domain}'. Subdomains widen the "
                    "attack surface and may expose forgotten or staging hosts."
                ),
                url=target,
                evidence={
                    "domain": domain,
                    "count": len(names),
                    "resolved": resolved,
                    "subdomains": reported,
                    "truncated": len(names) > _MAX_REPORTED,
                },
                remediation=(
                    "Review the exposed subdomains; decommission stale hosts and "
                    "ensure staging/internal environments are not publicly reachable."
                ),
            )
        ]

    async def _query_crtsh(
        self, session: aiohttp.ClientSession, domain: str
    ) -> set[str]:
        url = _CRT_SH.format(domain=domain)
        try:
            async with session.get(url, ssl=False) as resp:
                if resp.status != 200:
                    return set()
                raw = await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return set()

        try:
            entries = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return set()

        names: set[str] = set()
        for entry in entries:
            value = entry.get("name_value", "") if isinstance(entry, dict) else ""
            for line in value.splitlines():
                name = line.strip().lstrip("*.").lower()
                if name.endswith(domain) and _is_hostname(name):
                    names.add(name)
        names.discard(domain)
        return names

    async def _resolve_all(self, names: list[str]) -> list[str]:
        # Resolve a bounded sample to confirm liveness without flooding DNS.
        sample = names[:50]
        loop = asyncio.get_event_loop()
        resolved: list[str] = []
        for name in sample:
            try:
                await loop.getaddrinfo(name, None)
                resolved.append(name)
            except (OSError, asyncio.TimeoutError):
                continue
        return resolved


def _registrable_domain(host: str) -> str:
    # Heuristic: keep the last two labels (handles the common case; multi-part
    # TLDs like co.uk are not special-cased to avoid a dependency).
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _is_hostname(value: str) -> bool:
    if not value or len(value) > 253 or " " in value:
        return False
    return all(part and len(part) <= 63 for part in value.split("."))
