"""Plugin: detect error-based SQL injection in URL query parameters."""
from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

# Classic error signatures emitted by popular database engines when a
# malformed query reaches them. Matched case-insensitively against the body.
_SQL_ERRORS: list[str] = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "postgresql query failed",
    "sqlite3.operationalerror",
    "db2 sql error",
    "ora-01756",  # Oracle: quoted string not properly terminated
    "sqlstate",
]

# Payloads designed to break SQL string/quote context and surface an error.
_PAYLOADS: list[str] = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' --",
    "1' ORDER BY 1--",
]


class SqlInjectionPlugin(BasePlugin):
    """Probes each URL query parameter for error-based SQL injection."""

    name = "sql_injection"
    description = "Detect error-based SQL injection in URL query parameters"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        if not params:
            # Nothing to fuzz without query parameters.
            return findings

        for param_name in params:
            for payload in _PAYLOADS:
                # Replace only the current parameter's value with the payload.
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()

                try:
                    async with session.get(test_url, ssl=False) as resp:
                        body = (await resp.text()).lower()
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

                matched = next((e for e in _SQL_ERRORS if e in body), None)
                if matched is None:
                    continue

                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"SQL injection in parameter '{param_name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Injecting special characters into parameter "
                            f"'{param_name}' triggered a database error in the "
                            "response, indicating error-based SQL injection."
                        ),
                        url=test_url,
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "db_error": matched,
                        },
                        remediation=(
                            "Use parameterized queries (prepared statements) and "
                            "strictly validate or sanitise user-supplied input."
                        ),
                    )
                )
                # One confirmed payload per parameter is enough.
                break

        return findings
