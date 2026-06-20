"""Plugin: enumerate subdomains via Certificate Transparency (crt.sh)."""
from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

_CRT_SH = "https://crt.sh/?q=%.{domain}&output=json"
_MAX_REPORTED = 200

# Common subdomain prefixes probed via DNS when --subdomain-bruteforce is on.
_BRUTE_PREFIXES: list[str] = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "vpn", "admin", "portal", "test", "dev", "staging", "stage",
    "api", "app", "apps", "beta", "demo", "git", "gitlab", "jenkins", "ci",
    "cdn", "static", "assets", "img", "images", "media", "shop", "store",
    "blog", "news", "forum", "support", "help", "docs", "wiki", "status",
    "dashboard", "panel", "cpanel", "secure", "login", "auth", "sso", "m",
    "mobile", "internal", "intranet", "corp", "vpn2", "db", "database",
    "sql", "mysql", "redis", "cache", "monitor", "grafana", "kibana",
    "jira", "confluence", "mx", "mx1", "mx2", "old", "new", "backup",
]


class SubdomainsPlugin(BasePlugin):
    """Discovers subdomains via CT logs (crt.sh) and optional DNS brute force."""

    name = "subdomains"
    description = "Enumerate subdomains via Certificate Transparency and DNS brute force"

    def __init__(self, resolve: bool = True, bruteforce: bool = True) -> None:
        self._resolve = resolve
        self._bruteforce = bruteforce

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

        # DNS brute force: probe common prefixes and keep the ones that resolve.
        brute_hits: list[str] = []
        if self._bruteforce:
            candidates = [f"{p}.{domain}" for p in _BRUTE_PREFIXES]
            brute_hits = await self._resolve_all(candidates)
            names.update(brute_hits)

        if not names:
            return []

        # Confirm which CT-discovered names currently resolve in DNS.
        resolved = sorted(set(brute_hits))
        if self._resolve:
            ct_only = sorted(names - set(brute_hits))
            resolved = sorted(set(resolved) | set(await self._resolve_all(ct_only)))

        reported = sorted(names)[:_MAX_REPORTED]
        return [
            Finding(
                plugin=self.name,
                title=f"{len(names)} subdomain(s) discovered for {domain}",
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    f"Discovered {len(names)} subdomain(s) of '{domain}' via "
                    "Certificate Transparency logs (crt.sh) and DNS brute force. "
                    "Subdomains widen the attack surface and may expose forgotten "
                    "or staging hosts."
                ),
                url=target,
                evidence={
                    "domain": domain,
                    "count": len(names),
                    "resolved": resolved,
                    "bruteforce_hits": sorted(brute_hits),
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
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
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
        """Resolve *names* concurrently and return those that have DNS records."""
        if not names:
            return []
        loop = asyncio.get_running_loop()

        async def _one(name: str) -> str | None:
            try:
                await loop.getaddrinfo(name, None)
                return name
            except (OSError, asyncio.TimeoutError):
                return None

        # Bound concurrency so a large brute-force list doesn't swamp the resolver.
        sem = asyncio.Semaphore(20)

        async def _bounded(name: str) -> str | None:
            async with sem:
                return await _one(name)

        results = await asyncio.gather(*[_bounded(n) for n in names])
        return [n for n in results if n]


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
