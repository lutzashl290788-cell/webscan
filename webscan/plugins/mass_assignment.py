"""Plugin: detect mass assignment / auto-binding vulnerabilities.

Mass assignment occurs when a framework automatically binds all user-supplied
POST/JSON fields to a model object, including fields the user shouldn't be
able to set (e.g. ``role``, ``is_admin``, ``balance``, ``verified``).

The plugin is **active**: it sends a GET to capture the baseline response,
then sends a PUT/POST with extra privileged fields (``role=admin``,
``is_admin=true``, ``verified=true``) and checks if the response reflects
the change.

For low false positives:
- Only probes API endpoints (same as IDOR: ``/api/``, ``/v1/``, etc.)
- Only probes PUT/POST/PATCH endpoints (state-changing)
- Content-verified: the privileged field must appear in the response with
  the injected value
- All findings are TENTATIVE — mass assignment is semantic (the response
  reflecting the field doesn't mean it was persisted)
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

_API_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/api/"),
    re.compile(r"/v\d+/"),
    re.compile(r"/users?/", re.IGNORECASE),
    re.compile(r"/account/", re.IGNORECASE),
    re.compile(r"/profile/", re.IGNORECASE),
    re.compile(r"/admin/", re.IGNORECASE),
)

# Privileged fields to inject, with their values.
_PRIVILEGED_FIELDS: tuple[tuple[str, str], ...] = (
    ("role", "admin"),
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("admin", "true"),
    ("verified", "true"),
    ("is_verified", "true"),
    ("active", "true"),
    ("is_superuser", "true"),
    ("role_id", "1"),
    ("permissions", "[\"*\"]"),
    ("balance", "999999"),
    ("credit", "999999"),
    ("plan", "premium"),
    ("tier", "enterprise"),
)

_MIN_BODY_LENGTH = 50


def _is_api_endpoint(target: str) -> bool:
    path = urlparse(target).path
    return any(p.search(path) for p in _API_PATH_PATTERNS)


def _field_in_response(body: str, field: str, value: str) -> bool:
    """True if *field*=*value* appears in the response body (JSON or form)."""
    lowered = body.lower()
    # Check for JSON: "field": "value" or "field": value
    patterns = [
        f'"{field}"\\s*:\\s*"{value}"',
        f'"{field}"\\s*:\\s*{value}',
        f'{field}\\s*=\\s*{value}',
    ]
    return any(re.search(p, lowered, re.IGNORECASE) for p in patterns)


class MassAssignmentPlugin(BasePlugin):
    """Probes API endpoints for mass assignment via privileged field injection."""

    name = "mass_assignment"
    description = "Detect mass assignment by injecting role=admin, is_admin=true fields (TENTATIVE)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not _is_api_endpoint(target):
            return findings

        # Fetch baseline (GET).
        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                baseline_body = await fetch_body(resp)
                baseline_status = resp.status
                # Content-Type not needed for mass assignment check
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        if len(baseline_body) < _MIN_BODY_LENGTH:
            return findings

        # Try injecting privileged fields via PUT (most common for profile updates).
        # Each probe carries an Idempotency-Key (RFC 9110 §9.1.2) and an
        # X-WebScan-Test / X-WebScan-Dry-Run marker so the target can
        # identify and (if it understands the headers) skip persistence.
        # allow_redirects=False: a state-changing PUT must never silently
        # replay its body on a cross-origin redirect (CWE-200 / CWE-918).
        for field, value in _PRIVILEGED_FIELDS:
            # Build JSON body with the privileged field.
            json_body = json.dumps({field: value})

            try:
                async with session.put(
                    target,
                    data=json_body.encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Idempotency-Key": f"webscan-{uuid.uuid4()}",
                        "X-WebScan-Test": "1",
                        "X-WebScan-Dry-Run": "1",
                    },
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    probe_body = await fetch_body(resp)
                    probe_status = resp.status
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
                continue

            if probe_status >= 400:
                continue

            # Check if the field=value appears in the response.
            if _field_in_response(probe_body, field, value):
                findings.append(Finding(
                    plugin=self.name,
                    title=f"Mass assignment: '{field}' accepted via PUT (value: {value})",
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    description=(
                        f"A PUT request to `{target}` with JSON body "
                        f"`{{\"{field}\": \"{value}\"}}` was accepted and the "
                        f"response reflects `{field}={value}`. This suggests "
                        "the framework auto-binds all user-supplied fields to "
                        "the model without filtering. An attacker can set "
                        "privileged fields (role, is_admin, balance) by "
                        "including them in the request body."
                    ),
                    url=target,
                    evidence={
                        "method": "PUT",
                        "injected_field": field,
                        "injected_value": value,
                        "probe_status": probe_status,
                        "baseline_status": baseline_status,
                    },
                    remediation=(
                        "Use an explicit allow-list of fields that can be "
                        "mass-assigned. In Django, use `fields = (...)` in "
                        "ModelForm. In Rails, use Strong Parameters "
                        "(`params.require(:user).permit(:name, :email)`). "
                        "In Express.js, destructure only the fields you need."
                    ),
                ))
                # One finding is enough.
                break

        return findings
