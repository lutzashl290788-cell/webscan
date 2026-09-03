"""Guard against version drift across the package.

The version has historically been hard-coded in several modules, which meant a
release could ship with `pyproject.toml`, `webscan.__version__`, the webhook
payload and the `serve` API all disagreeing. These tests keep the single
source of truth honest.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import webscan

_ROOT = Path(__file__).resolve().parent.parent
_SEMVER = re.compile(r"^\d+\.\d+\.\d+([-.][A-Za-z0-9.]+)?$")

# Modules allowed to contain a literal version string: the one that defines it.
_VERSION_OWNER = "webscan/__init__.py"


def _pyproject_version() -> str:
    with (_ROOT / "pyproject.toml").open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


def test_version_is_valid_semver() -> None:
    assert _SEMVER.match(webscan.__version__), webscan.__version__


def test_package_version_matches_pyproject() -> None:
    assert webscan.__version__ == _pyproject_version()


def test_no_module_hard_codes_the_version() -> None:
    """No module may repeat the version literal — import __version__ instead."""
    current = webscan.__version__
    offenders = []
    for path in sorted((_ROOT / "webscan").rglob("*.py")):
        rel = path.relative_to(_ROOT).as_posix()
        if rel == _VERSION_OWNER:
            continue
        if current in path.read_text(encoding="utf-8"):
            offenders.append(rel)
    assert not offenders, (
        f"version literal {current!r} hard-coded in: {', '.join(offenders)}. "
        f"Import it from webscan instead: 'from webscan import __version__'."
    )


def test_changelog_documents_the_current_version() -> None:
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{webscan.__version__}]" in changelog, (
        f"CHANGELOG.md has no '## [{webscan.__version__}]' section."
    )


def test_release_notes_exist_for_the_current_version() -> None:
    notes = _ROOT / ".github" / "release-notes" / f"v{webscan.__version__}.md"
    assert notes.is_file(), (
        f"{notes.relative_to(_ROOT)} is missing; auto-release.yml reads it when "
        f"tag v{webscan.__version__} is pushed."
    )
