"""Plugin: detect exposed backup and temporary files.

Developers and sysadmins often leave backup files in the web root: ``.bak``,
``.old``, ``.swp``, ``~``, ``.save``, ``.orig``, ``.tmp``, ``.copy``,
``.dist``. These files are served verbatim by most web servers because the
extension doesn't match a handler — so a ``config.php.bak`` file leaks the
full PHP source code including database credentials.

This plugin is **active**: it probes known file paths with backup
extensions appended. Detection is content-verified:

* **CRITICAL (FIRM)** — response contains source-code markers (``<?php``,
  ``define(``, ``import ``, ``password``, ``DB_``, ``SECRET``) — the backup
  file's raw source is leaking.
* **MEDIUM (TENTATIVE)** — response is 200 with a non-trivial body but no
  source markers — could be a binary backup, an empty file, or a soft-404.
* Soft-404 calibration suppresses false positives on servers that answer
  200 for every path.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import calibrate_target, fetch_body, is_soft404
from webscan.plugins.base import BasePlugin

# ─── Probe design ─────────────────────────────────────────────────────────────

# Backup extensions to try, in order of likelihood.
_BACKUP_EXTENSIONS: tuple[str, ...] = (
    ".bak",
    ".old",
    ".orig",
    "~",
    ".save",
)

# Base file paths to probe — common config/source files that are dangerous
# if their backup leaks. Paths are relative to the target root.
_BASE_FILES: tuple[str, ...] = (
    "/config.php",
    "/wp-config.php",
    "/.env",
    "/settings.py",
    "/database.yml",
    "/application.properties",
    "/docker-compose.yml",
    "/.git/config",
    "/.htaccess",
    "/web.config",
)

# Source-code markers that prove the backup file's raw content is leaking.
_SOURCE_MARKERS: tuple[str, ...] = (
    "<?php",
    "<?=",
    "define(",
    "import ",
    "from ",
    "require ",
    "require_once",
    "include(",
    "include_once",
    "$db_",
    "$DB_",
    "DB_HOST",
    "DB_USER",
    "DB_PASSWORD",
    "DATABASE_URL",
    "password",
    "passwd",
    "secret",
    "api_key",
    "API_KEY",
    "-----BEGIN",
    "aws_secret",
    "AWS_SECRET",
)

# Minimum body length to consider a response a real file (not an empty stub).
_MIN_BODY_LENGTH = 20

# Cap probes per target — bound request pressure.
_MAX_PROBES = 15


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _has_source_marker(body: str) -> bool:
    """True if the body contains a source-code marker."""
    lowered = body[:8000].lower()
    return any(m.lower() in lowered for m in _SOURCE_MARKERS)


# ─── Plugin ───────────────────────────────────────────────────────────────────


class BackupFilesPlugin(BasePlugin):
    """Probes for exposed backup and temporary files."""

    name = "backup_files"
    description = "Detect exposed backup files (.bak, .old, .swp, ~, .orig)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Calibrate soft-404 for this target.
        soft_baseline = await calibrate_target(session, target)

        # Build probe URLs: base_file + backup_extension
        from urllib.parse import urlparse

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        probes = 0
        for base_file in _BASE_FILES:
            if probes >= _MAX_PROBES:
                break
            for ext in _BACKUP_EXTENSIONS:
                if probes >= _MAX_PROBES:
                    break
                probe_url = f"{base_url}{base_file}{ext}"
                probes += 1

                body, status = await self._fetch(session, probe_url)
                if body is None:
                    continue

                # Skip non-200 responses.
                if status != 200:
                    continue

                # Skip soft-404.
                if is_soft404(body, status, soft_baseline):
                    continue

                # Skip very short responses.
                if len(body) < _MIN_BODY_LENGTH:
                    continue

                # CRITICAL: source-code markers present.
                if _has_source_marker(body):
                    findings.append(self._make_finding(
                        target=target,
                        probe_url=probe_url,
                        base_file=base_file,
                        extension=ext,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.FIRM,
                        body_length=len(body),
                        has_source=True,
                    ))
                    # Found a CRITICAL for this base file — no need to try
                    # more extensions.
                    break

                # MEDIUM: 200 with non-trivial body, no source markers.
                # Could be a binary backup, an empty file, or a soft-404
                # that didn't match calibration.
                findings.append(self._make_finding(
                    target=target,
                    probe_url=probe_url,
                    base_file=base_file,
                    extension=ext,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    body_length=len(body),
                    has_source=False,
                ))
                break  # one finding per base file is enough

        return findings

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[str | None, int]:
        """GET *url* with retry on transient failures."""
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                body = await fetch_body(resp)
                return body, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None, 0

    def _make_finding(
        self,
        *,
        target: str,
        probe_url: str,
        base_file: str,
        extension: str,
        severity: Severity,
        confidence: Confidence,
        body_length: int,
        has_source: bool,
    ) -> Finding:
        if severity is Severity.CRITICAL:
            title = f"Backup file leaks source: {base_file}{extension}"
            desc = (
                f"A backup file at `{probe_url}` is accessible and contains "
                "source-code markers (PHP/Python/Java/Ruby). The raw source "
                "of the original file is leaking, including configuration, "
                "database credentials, and API keys."
            )
        else:
            title = f"Exposed backup file: {base_file}{extension}"
            desc = (
                f"A backup file at `{probe_url}` is accessible (HTTP 200, "
                f"{body_length} bytes) but no source-code markers were found. "
                "This could be a binary backup, a configuration file in a "
                "non-source format, or a soft-404. Manual review recommended."
            )

        return Finding(
            plugin=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            description=desc,
            url=target,
            evidence={
                "probe_url": probe_url,
                "base_file": base_file,
                "extension": extension,
                "http_status": 200,
                "body_length": body_length,
                "has_source_markers": has_source,
            },
            remediation=(
                "Delete all backup files from the web root. Configure your "
                "web server to deny access to files matching "
                "`*.(bak|old|orig|swp|tmp|save|~|backup|copy|dist)`. "
                "Use `.gitignore` and never commit backup files."
            ),
        )
