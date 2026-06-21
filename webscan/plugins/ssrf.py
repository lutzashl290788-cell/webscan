"""Plugin: detect server-side request forgery (SSRF) in URL parameters.

Detection is response-based (no out-of-band channel): a URL-like parameter is
pointed at internal/cloud-metadata endpoints, and the response is checked for
content only reachable if the *server* fetched it. This finds reflected SSRF;
fully blind SSRF needs an external collaborator and is out of scope.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, quote, urlencode, urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# Internal/metadata targets worth probing.
_PAYLOADS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
]

# Parameter names that commonly take a URL the server will fetch.
_URL_PARAMS = {
    "url", "uri", "target", "dest", "destination", "redirect", "redirect_uri",
    "next", "data", "reference", "site", "html", "feed", "host", "port",
    "to", "out", "view", "dir", "show", "navigation", "open", "image",
    "img", "source", "src", "load", "page", "fetch", "callback", "domain",
    "proxy", "u", "link", "request",
}

# Signatures that only appear if an internal service actually *responded*.
# Deliberately limited to fields present in a real metadata/service reply and
# NOT in the probe URL itself — the reflected payload is also stripped from the
# body before matching (see ``_matched_signature``), so an app that merely echoes
# the URL back can never trigger these.
_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("AWS metadata", re.compile(r"\b(ami-id|instance-id|instance-action|"
                                r"iam/security-credentials|reservation-id|"
                                r"security-groups)\b", re.IGNORECASE)),
    ("GCP metadata", re.compile(r"\b(computeMetadata|numeric-project-id|"
                                r"service-accounts)\b", re.IGNORECASE)),
    ("Redis", re.compile(r"-ERR wrong number|redis_version:", re.IGNORECASE)),
    ("Internal service", re.compile(r"\bConnection refused\b|"
                                    r"\bfailed to connect to (127\.0\.0\.1|localhost)",
                                    re.IGNORECASE)),
]


class SsrfPlugin(BasePlugin):
    """Probes URL-like query parameters for server-side request forgery."""

    name = "ssrf"
    description = "Detect reflected SSRF via internal/cloud-metadata endpoints"

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

        for param_name in params:
            if param_name.lower() not in _URL_PARAMS:
                continue

            for payload in _PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = parsed._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()

                try:
                    async with session.get(test_url, ssl=False) as resp:
                        body = await fetch_body(resp)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

                signal = _matched_signature(body, payload)
                if signal is None:
                    continue

                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Possible SSRF in parameter '{param_name}'",
                        severity=Severity.HIGH,
                        description=(
                            f"Parameter '{param_name}' caused the server to fetch an "
                            f"internal endpoint: the response contained {signal} "
                            "content, indicating server-side request forgery."
                        ),
                        url=test_url,
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "signal": signal,
                        },
                        remediation=(
                            "Validate and allow-list outbound URLs; block requests to "
                            "private/link-local ranges and cloud metadata IPs; resolve "
                            "and re-check the host after DNS resolution."
                        ),
                    )
                )
                break  # one confirmed payload per parameter is enough

        return findings


def _matched_signature(body: str, payload: str) -> str | None:
    """Match an internal-service signature against the response.

    The payload (and its URL-encoded form) is removed from the body first, so a
    page that merely *reflects* the injected URL — which itself contains strings
    like ``meta-data`` or ``metadata.google.internal`` — cannot trigger a match.
    Only content the server fetched from the internal endpoint remains.
    """
    cleaned = body.replace(payload, " ").replace(quote(payload, safe=""), " ")
    for label, pattern in _SIGNATURES:
        if pattern.search(cleaned):
            return label
    return None
