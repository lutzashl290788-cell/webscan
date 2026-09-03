"""Plugin: detect GraphQL endpoints with introspection enabled.

Introspection lets any client download the full API schema — every type, field
and mutation. That is convenient in development but, left on in production, it
hands attackers a complete map of the attack surface. This plugin POSTs a tiny
introspection query to a handful of conventional GraphQL paths and reports a
MEDIUM information-disclosure finding when the server answers with a schema.
"""
from __future__ import annotations

import json

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin
from webscan.retry import RetryConfig, request_with_retry
from webscan.utils.http import base_url

# Conventional locations a GraphQL endpoint is mounted at.
_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/query",
    "/graphql/console",
)

# Smallest query that proves introspection is enabled: ask for the schema's
# root query type. A live, introspectable endpoint echoes the type name back.
_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


class GraphqlPlugin(BasePlugin):
    """Probes common GraphQL paths and flags servers exposing introspection."""

    name = "graphql"
    description = "Detect GraphQL endpoints with introspection enabled"

    def __init__(self, retry: RetryConfig | None = None) -> None:
        self._retry = retry or RetryConfig(retries=1, base_delay=0.5)

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        base = base_url(target)
        findings: list[Finding] = []
        seen: set[str] = set()

        for path in _PATHS:
            url = base + path
            if url in seen:
                continue
            seen.add(url)

            resp = await request_with_retry(
                session, "POST", url,
                config=self._retry,
                json=_INTROSPECTION_QUERY, ssl=False,
            )
            if resp is None or resp.status >= 400:
                continue
            if _introspection_enabled(resp.text):
                findings.append(self._to_finding(url))

        return findings

    def _to_finding(self, url: str) -> Finding:
        return Finding(
            plugin=self.name,
            title="GraphQL introspection enabled",
            severity=Severity.MEDIUM,
            description=(
                f"The GraphQL endpoint at {url} answers introspection queries, "
                "exposing the full API schema (types, fields and mutations). This "
                "reveals the entire attack surface to anyone who asks."
            ),
            url=url,
            evidence={"endpoint": url, "introspection": True},
            remediation=(
                "Disable introspection in production (e.g. set "
                "`introspection: false` / a validation rule that blocks "
                "`__schema` queries), and restrict the endpoint to authenticated "
                "clients where possible."
            ),
        )


def _introspection_enabled(body: str) -> bool:
    """Return ``True`` if *body* is a GraphQL response carrying a schema."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    payload = data.get("data")
    if not isinstance(payload, dict):
        return False
    schema = payload.get("__schema")
    return isinstance(schema, dict) and "queryType" in schema
