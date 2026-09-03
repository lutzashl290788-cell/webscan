"""Plugin: detect path traversal / local file inclusion in query parameters."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# Traversal payloads targeting the canonical Unix and Windows victim files,
# including a few common encodings/depths to defeat naive filters.
_PAYLOADS: list[str] = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
]

# Signatures that only appear when the victim file is actually disclosed.
_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_WININI_RE = re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE)


class PathTraversalPlugin(BasePlugin):
    """Probes URL query parameters for path traversal / LFI."""

    name = "path_traversal"
    description = "Detect path traversal / local file inclusion in query parameters"

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

                victim = _matched_victim(body)
                if victim is None:
                    continue

                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Path traversal in parameter '{param_name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Parameter '{param_name}' returned the contents of a "
                            f"system file ({victim}) when injected with a traversal "
                            "payload, indicating path traversal / local file inclusion."
                        ),
                        url=test_url,
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "disclosed_file": victim,
                        },
                        remediation=(
                            "Reject path separators and traversal sequences in "
                            "user input; resolve and confirm the canonical path stays "
                            "within an allowed base directory before reading files."
                        ),
                    )
                )
                break  # one confirmed payload per parameter is enough

        return findings


def _matched_victim(body: str) -> str | None:
    if _PASSWD_RE.search(body):
        return "/etc/passwd"
    if _WININI_RE.search(body):
        return "windows/win.ini"
    return None
