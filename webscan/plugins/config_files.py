"""Plugin: scan for publicly accessible configuration / sensitive files."""
from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin
from webscan.plugins.soft404 import calibrate, read_finding_body

# Extensions the server may *execute* instead of serving as source. A request
# for one of these that returns 200 with an empty body (or rendered HTML)
# means the script ran and disclosed nothing — NOT an exposure. We only flag
# these when the body actually contains source markers (see ``_SOURCE_MARKERS``).
_EXECUTABLE_EXT: tuple[str, ...] = (
    ".php", ".py", ".cgi", ".pl", ".rb", ".asp", ".aspx", ".jsp",
)

# Substrings that betray leaked *source* of an executable script (lower-cased).
# Their presence means the file was served verbatim rather than executed.
_SOURCE_MARKERS: tuple[str, ...] = (
    "<?php", "<?=", "<%", "#!/", "import ", "define(", "require(", "require_once",
    "db_password", "db_name", "db_user", "secret_key", "django",
)

# (path, human label)
_CONFIG_FILES: list[tuple[str, str]] = [
    ("/.env", "Environment variables file"),
    ("/.env.local", "Local environment override"),
    ("/.env.production", "Production environment file"),
    ("/.env.backup", "Backup environment file"),
    ("/.env.old", "Old environment file"),
    ("/.git/config", "Git repository config"),
    ("/.git/HEAD", "Git HEAD reference"),
    ("/.git/COMMIT_EDITMSG", "Git last commit message"),
    ("/.svn/entries", "SVN repository entries"),
    ("/docker-compose.yml", "Docker Compose configuration"),
    ("/docker-compose.yaml", "Docker Compose configuration"),
    ("/docker-compose.override.yml", "Docker Compose override"),
    ("/Dockerfile", "Docker build definition"),
    ("/.htpasswd", "Apache password file"),
    ("/.htaccess", "Apache access control"),
    ("/web.config", "IIS web configuration"),
    ("/config.php", "PHP application config"),
    ("/wp-config.php", "WordPress configuration"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/configuration.php", "Joomla configuration"),
    ("/config.yml", "YAML configuration"),
    ("/config.yaml", "YAML configuration"),
    ("/config.json", "JSON configuration"),
    ("/settings.py", "Python settings module"),
    ("/local_settings.py", "Python local settings"),
    ("/database.yml", "Database credentials"),
    ("/database.yaml", "Database credentials"),
    ("/secrets.yml", "Secrets file"),
    ("/secrets.yaml", "Secrets file"),
    ("/package.json", "Node.js package manifest"),
    ("/composer.json", "PHP Composer manifest"),
    ("/.travis.yml", "Travis CI configuration"),
    ("/.github/workflows", "GitHub Actions workflows"),
    ("/.DS_Store", "macOS directory metadata"),
    ("/Makefile", "Build automation file"),
    ("/phpinfo.php", "PHP info disclosure"),
    ("/info.php", "PHP info disclosure"),
    ("/test.php", "PHP test file"),
    ("/backup.sql", "SQL database backup"),
    ("/dump.sql", "SQL database dump"),
    ("/db.sql", "SQL database file"),
    ("/backup.zip", "Archive backup"),
    ("/backup.tar.gz", "Archive backup"),
    ("/site.tar.gz", "Site archive"),
    ("/www.zip", "Site archive"),
    ("/id_rsa", "Private SSH key"),
    ("/id_rsa.pub", "Public SSH key"),
    ("/.ssh/id_rsa", "Private SSH key (ssh dir)"),
    ("/server.key", "TLS private key"),
    ("/private.key", "Private key"),
    ("/certificate.pem", "TLS certificate"),
]

# Paths whose exposure is unconditionally CRITICAL
_CRITICAL: frozenset[str] = frozenset({
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.env.old",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/config.php",
    "/configuration.php",
    "/id_rsa",
    "/.ssh/id_rsa",
    "/server.key",
    "/private.key",
    "/secrets.yml",
    "/secrets.yaml",
})

# Paths whose exposure is HIGH
_HIGH: frozenset[str] = frozenset({
    "/.git/config",
    "/.git/HEAD",
    "/.git/COMMIT_EDITMSG",
    "/.htpasswd",
    "/database.yml",
    "/database.yaml",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.tar.gz",
    "/www.zip",
})


class ConfigFilesPlugin(BasePlugin):
    """Scans for exposed configuration files and sensitive artefacts."""

    name = "config_files"
    description = "Detect publicly accessible config/sensitive files (.env, .git, etc.)"

    def __init__(self, soft_404: bool = False) -> None:
        self.soft_404 = soft_404

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        parsed = urlsplit(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
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
                    if resp.status != 200:
                        return None

                    body = await read_finding_body(resp)

                    # Drop files that merely return the server's soft-404 page.
                    if baseline is not None and baseline.matches(resp.status, body):
                        return None

                    if not _is_exposed(path, body):
                        return None

                    return Finding(
                        plugin=self.name,
                        title=f"Exposed file: {path}",
                        severity=_classify(path),
                        description=(
                            f"{label} is publicly readable at {url}. "
                            "Sensitive credentials or internal data may be exposed."
                        ),
                        url=url,
                        evidence={
                            "http_status": resp.status,
                            "content_type": resp.headers.get("Content-Type", ""),
                            "content_length": resp.headers.get("Content-Length", ""),
                            "body_bytes": len(body),
                        },
                        remediation=(
                            f"Block access to '{path}' in your web-server config "
                            "or move the file outside the document root."
                        ),
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None

        results = await asyncio.gather(*[_check(p, lbl) for p, lbl in _CONFIG_FILES])
        findings = [f for f in results if f is not None]
        return findings


def _is_exposed(path: str, body: str) -> bool:
    """Decide whether a 200 response genuinely *discloses* the file.

    The naive "status == 200 means exposed" rule produces false positives on
    server-executable scripts: a request for ``/wp-config.php`` runs the PHP
    interpreter, which emits an **empty body** (or rendered HTML) and leaks
    nothing. A real disclosure either serves the raw source or returns actual
    file contents. Concretely:

    * Empty / whitespace-only body  -> never an exposure.
    * Executable script (.php, .py, ...) -> exposed only if the body carries a
      source marker (``<?php``, ``import ``, ``define(`` …), proving the source
      was served verbatim rather than executed.
    * Any other file with a non-empty body -> exposed (soft-404 echoes are
      already filtered upstream by the calibrated baseline).
    """
    if not body.strip():
        return False
    if path.endswith(_EXECUTABLE_EXT):
        lowered = body.lower()
        return any(marker in lowered for marker in _SOURCE_MARKERS)
    return True


def _classify(path: str) -> Severity:
    if path in _CRITICAL:
        return Severity.CRITICAL
    if path in _HIGH:
        return Severity.HIGH
    return Severity.MEDIUM
