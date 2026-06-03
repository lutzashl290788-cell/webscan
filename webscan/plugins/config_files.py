"""Plugin: scan for publicly accessible configuration / sensitive files."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

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

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        base = target.rstrip("/")
        findings: list[Finding] = []

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


def _classify(path: str) -> Severity:
    if path in _CRITICAL:
        return Severity.CRITICAL
    if path in _HIGH:
        return Severity.HIGH
    return Severity.MEDIUM
