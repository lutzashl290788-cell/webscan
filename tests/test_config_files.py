"""Tests for the exposed-config-files plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.config_files import ConfigFilesPlugin

_BASE = "https://example.com"

# Realistic served-source bodies for the paths used in tests.
_ENV_BODY = "DB_PASSWORD=s3cret\nAPI_KEY=abcdef\n"
_GIT_CONFIG_BODY = "[core]\n\trepositoryformatversion = 0\n"
_PACKAGE_JSON_BODY = '{\n  "name": "app",\n  "version": "1.0.0"\n}\n'
_WP_CONFIG_SOURCE = "<?php\ndefine('DB_PASSWORD', 'hunter2');\n"


class _Resp:
    def __init__(self, status: int, body: str = "") -> None:
        self.status = status
        self._body = body
        self.headers: dict[str, str] = {}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kwargs: object) -> str:
        return self._body


class _Session:
    """Returns 200 with a body for configured paths, 404 otherwise."""

    def __init__(self, present: dict[str, str]) -> None:
        self._present = present

    def get(self, url: str, **_kw: object) -> _Resp:
        path = url[len(_BASE):]
        if path in self._present:
            return _Resp(200, self._present[path])
        return _Resp(404)


async def test_flags_exposed_env_as_critical() -> None:
    session = _Session({"/.env": _ENV_BODY})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].title == "Exposed file: /.env"
    assert findings[0].severity is Severity.CRITICAL


async def test_severity_classification() -> None:
    session = _Session(
        {"/.git/config": _GIT_CONFIG_BODY, "/package.json": _PACKAGE_JSON_BODY}
    )
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    by_path = {f.title: f.severity for f in findings}

    assert by_path["Exposed file: /.git/config"] is Severity.HIGH
    assert by_path["Exposed file: /package.json"] is Severity.MEDIUM


async def test_clean_target_no_findings() -> None:
    session = _Session({})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_executed_php_empty_body_not_flagged() -> None:
    """Regression for #32: wp-config.php that runs and emits nothing is not a leak."""
    session = _Session({"/wp-config.php": ""})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_executed_php_rendered_html_not_flagged() -> None:
    """An executed PHP file that renders HTML (no source markers) is not a leak."""
    session = _Session({"/config.php": "<!DOCTYPE html><html><body>ok</body></html>"})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_leaked_php_source_is_flagged() -> None:
    """A wp-config.php served as raw source (markers present) IS a critical leak."""
    session = _Session({"/wp-config.php": _WP_CONFIG_SOURCE})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].title == "Exposed file: /wp-config.php"
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["body_bytes"] == len(_WP_CONFIG_SOURCE)


async def test_empty_non_executable_file_not_flagged() -> None:
    """An empty data file (0 bytes) discloses nothing and is not flagged."""
    session = _Session({"/database.yml": "   \n"})
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_probes_origin_when_target_has_query() -> None:
    """Crawled URLs must not become the base for root file probes."""
    session = _Session({"/.env": _ENV_BODY})
    findings = await ConfigFilesPlugin().run(
        "https://example.com/search?q=invoice", session  # type: ignore[arg-type]
    )
    assert [f.title for f in findings] == ["Exposed file: /.env"]
