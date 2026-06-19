"""Plugin: GraphQL depth attack + field suggestion information disclosure.

Extends the existing `graphql` plugin with two additional checks:

1. **Depth attack (MEDIUM, TENTATIVE)** — sends a deeply nested query
   (depth 50) and checks if the server processes it (200 response) or
   rejects it (400 with "depth" error). A 200 means the server is
   vulnerable to DoS via deep queries.

2. **Field suggestion (LOW, INFORMATIONAL)** — sends a query with a
   typo'd field name (`__typo__`) and checks if the response contains
   "Did you mean" — which leaks the real schema field names.

Both checks only fire on URLs whose path contains `/graphql`.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

_GRAPHQL_PATH = "graphql"
_DEPTH_QUERY = '{"query":"' + " ".join(["{hero{name"] * 50) + " ".join(["}"] * 50) + '"}'
_FIELD_SUGGESTION_QUERY = '{"query":"{ __typo__ }"}'
_MIN_BODY_LENGTH = 20


class GraphqlDepthPlugin(BasePlugin):
    """Probes GraphQL endpoints for depth attacks and field suggestions."""

    name = "graphql_depth"
    description = "Detect GraphQL depth attacks and field-suggestion information disclosure"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if _GRAPHQL_PATH not in target.lower():
            return findings

        # Check 1: depth attack.
        depth_body, depth_status = await self._post(session, target, _DEPTH_QUERY)
        if depth_body is not None and depth_status == 200:
            if len(depth_body) >= _MIN_BODY_LENGTH:
                findings.append(Finding(
                    plugin=self.name,
                    title="GraphQL depth attack: server accepts deeply nested queries (DoS)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    description=(
                        "The GraphQL endpoint accepted a query with depth 50 "
                        "and returned HTTP 200. A malicious query with depth "
                        "1000+ can cause exponential CPU/memory usage, leading "
                        "to denial of service. The server should enforce a "
                        "maximum query depth limit."
                    ),
                    url=target,
                    evidence={
                        "probe_query": "depth=50 nested query",
                        "http_status": depth_status,
                        "response_length": len(depth_body),
                    },
                    remediation=(
                        "Enforce a maximum query depth limit (e.g. 10) using "
                        "graphql-depth-limit (Node.js) or graphql-core's "
                        "validation rules (Python). Also implement query "
                        "complexity analysis and rate limiting."
                    ),
                ))

        # Check 2: field suggestion.
        suggest_body, suggest_status = await self._post(
            session, target, _FIELD_SUGGESTION_QUERY
        )
        if suggest_body is not None and "did you mean" in suggest_body.lower():
            findings.append(Finding(
                plugin=self.name,
                title="GraphQL field suggestion leaks schema (information disclosure)",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                description=(
                    "The GraphQL endpoint responds to a typo'd field name "
                    "(`__typo__`) with a 'Did you mean ...' suggestion. This "
                    "leaks real schema field names to an attacker, who can "
                    "use them to enumerate the API surface."
                ),
                url=target,
                evidence={
                    "probe_query": _FIELD_SUGGESTION_QUERY,
                    "http_status": suggest_status,
                },
                remediation=(
                    "Disable field suggestions in production. In Apollo "
                    "Server: set `formatError` to strip suggestions. In "
                    "graphql-go: set `DisableSuggestion: true`."
                ),
            ))

        return findings

    async def _post(
        self,
        session: aiohttp.ClientSession,
        url: str,
        body: str,
    ) -> tuple[str | None, int]:
        try:
            async with session.post(
                url,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                text = await resp.text(errors="ignore")
                return text, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None, 0
