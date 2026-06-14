"""Plugin: detect accessible sensitive directories and directory listings."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin
from webscan.plugins.soft404 import calibrate

_READ_LIMIT = 4096  # bytes — enough to detect "Index of /" listings

# (path, human label)
_DIRECTORIES: list[tuple[str, str]] = [
    ("/.git/", "Git repository root"),
    ("/.svn/", "SVN repository root"),
    ("/admin/", "Admin panel"),
    ("/admin", "Admin panel (no trailing slash)"),
    ("/administrator/", "Administrator panel"),
    ("/wp-admin/", "WordPress admin"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/phpmyadmin", "phpMyAdmin (no trailing slash)"),
    ("/pma/", "phpMyAdmin alias"),
    ("/backup/", "Backup directory"),
    ("/backups/", "Backups directory"),
    ("/bak/", "Backup directory (bak)"),
    ("/config/", "Configuration directory"),
    ("/configs/", "Configurations directory"),
    ("/conf/", "Configuration directory (conf)"),
    ("/logs/", "Log files directory"),
    ("/log/", "Log files directory (log)"),
    ("/uploads/", "File uploads directory"),
    ("/upload/", "File upload directory"),
    ("/files/", "Files directory"),
    ("/file/", "File directory"),
    ("/tmp/", "Temporary files directory"),
    ("/temp/", "Temporary files directory"),
    ("/cache/", "Cache directory"),
    ("/private/", "Private directory"),
    ("/secret/", "Secret directory"),
    ("/hidden/", "Hidden directory"),
    ("/api/", "API root"),
    ("/api/v1/", "API v1 root"),
    ("/api/v2/", "API v2 root"),
    ("/test/", "Test directory"),
    ("/tests/", "Tests directory"),
    ("/dev/", "Development directory"),
    ("/staging/", "Staging directory"),
    ("/debug/", "Debug interface"),
    ("/console/", "Console interface"),
    ("/db/", "Database directory"),
    ("/sql/", "SQL files directory"),
    ("/shell/", "Shell scripts directory"),
    ("/wp-content/uploads/", "WordPress uploads"),
    ("/wp-includes/", "WordPress core includes"),
    ("/vendor/", "Composer vendor packages"),
    ("/node_modules/", "Node.js dependencies"),
    ("/src/", "Source code directory"),
    ("/source/", "Source code directory"),
    ("/static/", "Static assets directory"),
    ("/assets/", "Assets directory"),
    ("/media/", "Media files directory"),
    ("/data/", "Data directory"),
    ("/storage/", "Storage directory"),
]

_CRITICAL_DIRS: frozenset[str] = frozenset({
    "/.git/",
    "/.svn/",
    "/phpmyadmin/",
    "/phpmyadmin",
    "/pma/",
    "/admin/",
    "/admin",
    "/administrator/",
    "/wp-admin/",
})

_HIGH_DIRS: frozenset[str] = frozenset({
    "/backup/",
    "/backups/",
    "/bak/",
    "/config/",
    "/configs/",
    "/conf/",
    "/db/",
    "/sql/",
    "/private/",
    "/secret/",
    "/hidden/",
})

_LISTING_INDICATORS: tuple[str, ...] = (
    "index of /",
    "directory listing",
    "parent directory",
    "[to parent directory]",
)


class DirectoriesPlugin(BasePlugin):
    """Checks for accessible sensitive directories and directory listing enablement.

    :param soft_404: When ``True``, calibrate against a non-existent path first
                     and suppress findings that match the server's soft-404
                     template (a body returned with ``200``/``403`` for paths
                     that do not actually exist). Off by default.
    """

    name = "directories"
    description = "Probe sensitive directories and detect open directory listings"

    def __init__(self, soft_404: bool = False) -> None:
        self.soft_404 = soft_404

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        base = target.rstrip("/")
        findings: list[Finding] = []

        baseline = await calibrate(session, base) if self.soft_404 else None

        async def _check(path: str, label: str) -> Finding | None:
            url = f"{base}{path}"
            try:
                async with session.get(
                    url,
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    status = resp.status
                    if status not in (200, 403):
                        return None

                    is_listing = False
                    body_preview = ""
                    body_text = ""
                    if status == 200:
                        raw = await resp.content.read(_READ_LIMIT)
                        body_text = raw.decode("utf-8", errors="ignore").lower()
                        is_listing = any(ind in body_text for ind in _LISTING_INDICATORS)
                        body_preview = body_text[:120].replace("\n", " ")

                    # Suppress paths that merely echo the server's soft-404
                    # template. A genuine directory listing is never a soft-404,
                    # so it is always kept.
                    if (
                        baseline is not None
                        and not is_listing
                        and baseline.matches(status, body_text)
                    ):
                        return None

                    severity = _classify(path, status, is_listing)

                    if status == 403 and path not in _CRITICAL_DIRS:
                        # 403 on a non-critical path — low informational value
                        return None

                    return Finding(
                        plugin=self.name,
                        title=(
                            f"Directory listing enabled: {path}"
                            if is_listing
                            else f"Accessible directory: {path}"
                        ),
                        severity=severity,
                        description=_build_description(label, url, status, is_listing),
                        url=url,
                        evidence={
                            "http_status": status,
                            "directory_listing": is_listing,
                            "body_preview": body_preview,
                        },
                        remediation=(
                            "Disable directory listing (e.g. Options -Indexes in Apache) "
                            "and restrict access to sensitive directories via web-server ACLs."
                        ),
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None

        results = await asyncio.gather(*[_check(p, lbl) for p, lbl in _DIRECTORIES])
        findings = [f for f in results if f is not None]
        return findings


def _classify(path: str, status: int, is_listing: bool) -> Severity:
    if is_listing:
        return Severity.HIGH
    if status == 200 and path in _CRITICAL_DIRS:
        return Severity.CRITICAL
    if status == 200 and path in _HIGH_DIRS:
        return Severity.HIGH
    if status == 200:
        return Severity.MEDIUM
    # 403 on a critical path — at least confirms existence
    return Severity.LOW


def _build_description(
    label: str,
    url: str,
    status: int,
    is_listing: bool,
) -> str:
    if is_listing:
        return (
            f"{label} at {url} is accessible (HTTP {status}) and "
            "directory listing is enabled. All files are enumerable."
        )
    if status == 403:
        return (
            f"{label} at {url} returned HTTP 403 (Forbidden), "
            "confirming the directory exists even though access is blocked."
        )
    return (
        f"{label} at {url} returned HTTP {status}. "
        "The directory may expose sensitive data or attack surface."
    )
