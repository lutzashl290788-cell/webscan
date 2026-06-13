"""Plugin: detect leaked API keys / secrets in HTML and served JavaScript.

White-hat by design: it helps an operator find credentials accidentally
exposed in their own front-end before attackers do. Matched secrets are
redacted in the finding (only a short prefix is kept) so the report itself
never leaks the full value.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin
from webscan.utils.html import parse_html

# (label, severity, compiled pattern). Patterns are deliberately high-confidence
# (structured / prefixed tokens) to keep false positives low.
_SECRET_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("AWS Access Key ID", Severity.CRITICAL, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Anthropic API key", Severity.CRITICAL, re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", Severity.CRITICAL, re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("Google API key", Severity.HIGH, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live secret key", Severity.CRITICAL, re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}")),
    ("GitHub token", Severity.HIGH, re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    ("GitHub fine-grained token", Severity.HIGH, re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}")),
    ("Slack token", Severity.HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("HuggingFace token", Severity.HIGH, re.compile(r"\bhf_[0-9A-Za-z]{30,}")),
    ("Google OAuth client secret", Severity.HIGH, re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}")),
    ("Private key block", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    # A JWT (three base64url segments, header beginning "eyJ" == '{"'). May carry
    # session claims; treat an exposed one as a leaked credential.
    ("JSON Web Token (JWT)", Severity.MEDIUM,
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # Generic "api_key = '...'" / "secret: \"...\"" assignments with a long value.
    # Quoted + length-bounded to keep false positives low.
    ("Generic API key / secret", Severity.MEDIUM, re.compile(
        r"""(?ix)
        \b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\b
        ['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]
        """,
    )),
]

_MAX_SCRIPTS = 15  # bound the number of external JS files fetched per target


class SecretsPlugin(BasePlugin):
    """Scans page HTML and same-origin JavaScript for leaked credentials."""

    name = "secrets"
    description = "Detect leaked API keys / secrets in HTML and served JavaScript"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        body = await self._get(session, target)
        if body is None:
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()  # (label, redacted) dedupe

        self._scan_text(target, body, findings, seen)

        # Fetch same-origin scripts referenced by the page and scan those too.
        target_host = urlparse(target).netloc
        page = parse_html(body, base=target)
        scripts = [
            s for s in page.links
            if s.endswith(".js") and urlparse(s).netloc == target_host
        ][:_MAX_SCRIPTS]

        for src in scripts:
            js = await self._get(session, src)
            if js:
                self._scan_text(src, js, findings, seen)

        return findings

    def _scan_text(
        self,
        location: str,
        text: str,
        findings: list[Finding],
        seen: set[tuple[str, str]],
    ) -> None:
        for label, severity, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                secret = match.group(0)
                redacted = _redact(secret)
                key = (label, redacted)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Exposed {label}",
                        severity=severity,
                        description=(
                            f"A value matching a {label} was found in client-side "
                            f"content served at {location}. Anything in HTML/JS is "
                            "public; treat this credential as compromised."
                        ),
                        url=location,
                        evidence={"type": label, "match_preview": redacted},
                        remediation=(
                            "Revoke and rotate this credential immediately. Never ship "
                            "secrets to the browser — keep them server-side and proxy "
                            "calls through your backend."
                        ),
                    )
                )

    async def _get(self, session: aiohttp.ClientSession, url: str) -> str | None:
        try:
            async with session.get(url, ssl=False) as resp:
                return await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None


def _redact(secret: str) -> str:
    """Keep a short identifying prefix; mask the rest so reports stay safe."""
    keep = min(8, max(4, len(secret) // 4))
    return secret[:keep] + "…[REDACTED]"
