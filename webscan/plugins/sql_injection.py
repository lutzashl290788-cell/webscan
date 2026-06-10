"""Plugin: detect SQL injection (error-based, boolean-blind, time-blind)."""
from __future__ import annotations

import asyncio
from difflib import SequenceMatcher
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse

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

# Boolean-blind pairs: a logically TRUE and logically FALSE condition. A page
# that renders like the original for TRUE but differently for FALSE indicates
# the parameter is evaluated inside a SQL statement.
_BOOLEAN_PAIRS: list[tuple[str, str]] = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
]

# Time-blind payloads keyed by engine; each should stall the response ~DELAY s.
_DELAY_SECONDS = 5
_TIME_PAYLOADS: list[str] = [
    f"' AND SLEEP({_DELAY_SECONDS})-- -",  # MySQL
    f"'; SELECT pg_sleep({_DELAY_SECONDS})-- -",  # PostgreSQL
    f"'; WAITFOR DELAY '0:0:{_DELAY_SECONDS}'-- -",  # MSSQL
    f"' AND {_DELAY_SECONDS}=DBMS_LOCK.SLEEP({_DELAY_SECONDS})-- -",  # Oracle
]

# Response-similarity threshold: TRUE/FALSE bodies differing by more than this
# (i.e. similarity below it) are treated as a boolean-blind signal.
_SIMILARITY_THRESHOLD = 0.95


class SqlInjectionPlugin(BasePlugin):
    """Probes URL query parameters for error-, boolean- and time-based SQLi."""

    name = "sql_injection"
    description = "Detect error-, boolean- and time-based SQL injection"

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

        for param_name, values in params.items():
            original_value = values[0] if values else ""

            error_finding = await self._check_error_based(
                parsed, params, param_name, session
            )
            if error_finding is not None:
                findings.append(error_finding)
                continue  # strongest signal — no need to also probe blind

            boolean_finding = await self._check_boolean_blind(
                parsed, params, param_name, original_value, session
            )
            if boolean_finding is not None:
                findings.append(boolean_finding)
                continue

            time_finding = await self._check_time_blind(
                parsed, params, param_name, original_value, session
            )
            if time_finding is not None:
                findings.append(time_finding)

        return findings

    # ------------------------------------------------------------------
    # Detection strategies
    # ------------------------------------------------------------------

    async def _check_error_based(
        self,
        parsed: ParseResult,
        params: dict[str, list[str]],
        param_name: str,
        session: aiohttp.ClientSession,
    ) -> Finding | None:
        for payload in _PAYLOADS:
            url = _build_url(parsed, params, param_name, payload)
            body = await self._get_text(session, url)
            if body is None:
                continue
            matched = next((e for e in _SQL_ERRORS if e in body.lower()), None)
            if matched is None:
                continue
            return Finding(
                plugin=self.name,
                title=f"SQL injection in parameter '{param_name}'",
                severity=Severity.CRITICAL,
                description=(
                    f"Injecting special characters into parameter '{param_name}' "
                    "triggered a database error in the response, indicating "
                    "error-based SQL injection."
                ),
                url=url,
                evidence={
                    "type": "error-based",
                    "parameter": param_name,
                    "payload": payload,
                    "db_error": matched,
                },
                remediation=(
                    "Use parameterized queries (prepared statements) and strictly "
                    "validate or sanitise user-supplied input."
                ),
            )
        return None

    async def _check_boolean_blind(
        self,
        parsed: ParseResult,
        params: dict[str, list[str]],
        param_name: str,
        original_value: str,
        session: aiohttp.ClientSession,
    ) -> Finding | None:
        for true_suffix, false_suffix in _BOOLEAN_PAIRS:
            true_url = _build_url(
                parsed, params, param_name, original_value + true_suffix
            )
            false_url = _build_url(
                parsed, params, param_name, original_value + false_suffix
            )

            true_body = await self._get_text(session, true_url)
            false_body = await self._get_text(session, false_url)
            if true_body is None or false_body is None:
                continue

            true_false_sim = _similarity(true_body, false_body)
            # TRUE differs meaningfully from FALSE → conditional SQL evaluation.
            if true_false_sim < _SIMILARITY_THRESHOLD:
                return Finding(
                    plugin=self.name,
                    title=f"Boolean-based blind SQL injection in '{param_name}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Parameter '{param_name}' produces different responses for "
                        "logically TRUE vs FALSE SQL conditions, indicating "
                        "boolean-based blind SQL injection."
                    ),
                    url=true_url,
                    evidence={
                        "type": "boolean-blind",
                        "parameter": param_name,
                        "true_payload": true_suffix,
                        "false_payload": false_suffix,
                        "similarity": round(true_false_sim, 3),
                    },
                    remediation=(
                        "Use parameterized queries (prepared statements) and strictly "
                        "validate or sanitise user-supplied input."
                    ),
                )
        return None

    async def _check_time_blind(
        self,
        parsed: ParseResult,
        params: dict[str, list[str]],
        param_name: str,
        original_value: str,
        session: aiohttp.ClientSession,
    ) -> Finding | None:
        # Establish a quick baseline; if the site is already slow, skip to avoid
        # false positives.
        baseline_url = _build_url(parsed, params, param_name, original_value)
        baseline = await self._timed_get(session, baseline_url)
        if baseline is None or baseline >= _DELAY_SECONDS:
            return None

        for payload in _TIME_PAYLOADS:
            url = _build_url(parsed, params, param_name, original_value + payload)
            elapsed = await self._timed_get(session, url)
            if elapsed is None:
                continue
            # Require the delay to clearly exceed baseline by most of DELAY.
            if elapsed >= baseline + (_DELAY_SECONDS * 0.8):
                return Finding(
                    plugin=self.name,
                    title=f"Time-based blind SQL injection in '{param_name}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Parameter '{param_name}' delayed the response by "
                        f"~{_DELAY_SECONDS}s when injected with a database sleep "
                        "payload, indicating time-based blind SQL injection."
                    ),
                    url=url,
                    evidence={
                        "type": "time-blind",
                        "parameter": param_name,
                        "payload": payload,
                        "baseline_s": round(baseline, 2),
                        "delayed_s": round(elapsed, 2),
                    },
                    remediation=(
                        "Use parameterized queries (prepared statements) and strictly "
                        "validate or sanitise user-supplied input."
                    ),
                )
        return None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_text(
        self, session: aiohttp.ClientSession, url: str
    ) -> str | None:
        try:
            async with session.get(url, ssl=False) as resp:
                return await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    async def _timed_get(
        self, session: aiohttp.ClientSession, url: str
    ) -> float | None:
        loop = asyncio.get_event_loop()
        start = loop.time()
        try:
            async with session.get(url, ssl=False) as resp:
                await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        return loop.time() - start


# ----------------------------------------------------------------------
# Module helpers
# ----------------------------------------------------------------------

def _build_url(
    parsed: ParseResult,
    params: dict[str, list[str]],
    param_name: str,
    payload: str,
) -> str:
    test_params = dict(params)
    test_params[param_name] = [payload]
    return parsed._replace(query=urlencode(test_params, doseq=True)).geturl()


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()
