"""YAML scan-profile / config-file support.

A config file lets a team keep reusable scan settings under version control
instead of memorising long command lines. Two shapes are accepted:

Flat — a single implicit profile::

    plugins: [headers, cookies, ssl_tls]
    concurrency: 20
    timeout: 15
    format: [json, sarif]
    output: ./reports/scan

Named profiles — selected with ``--profile NAME``::

    profiles:
      quick:
        plugins: [headers, cookies]
        concurrency: 30
      deep:
        plugins: [headers, sql_injection, xss, ssrf]
        crawl: true
        depth: 3

Precedence is resolved by the CLI: explicit command-line flags override config
values, which in turn override the built-in defaults. Only a known, safe set of
keys is honoured; anything else is ignored.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Config keys map 1:1 to argparse ``dest`` names. Restricting to this set keeps a
# profile from injecting unexpected attributes into the parsed namespace.
ALLOWED_KEYS: frozenset[str] = frozenset({
    "plugins",
    "concurrency",
    "timeout",
    "format",
    "output",
    "crawl",
    "depth",
    "max_urls",
    "scope",
    "exclude",
    "min_severity",
    "fail_on",
    "safe_mode",
    "delay",
    "rate_limit",
    "retries",
    "retry_backoff",
    "verbose",
    "quiet",
    "anonymize",
})


class ConfigError(Exception):
    """Raised when a config file is missing, malformed, or names a bad profile."""


def load_profile(path: str | Path, profile: str | None = None) -> dict[str, Any]:
    """Load *path* and return the chosen profile's settings as a dict.

    :param path:    Path to the YAML config file.
    :param profile: Named profile to select. Required if the file uses the
                    ``profiles:`` shape and has no ``default`` profile; ignored
                    for a flat config (raises if a name is given but absent).
    :raises ConfigError: on a missing file, invalid YAML, non-mapping content,
                         or an unknown profile name.
    """
    file = Path(path)
    if not file.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}.")

    section = _select_section(raw, profile, path)
    return {k: v for k, v in section.items() if k in ALLOWED_KEYS}


def _select_section(
    raw: dict[str, Any], profile: str | None, path: str | Path
) -> dict[str, Any]:
    """Pick the relevant settings mapping from a parsed config document."""
    profiles = raw.get("profiles")
    if isinstance(profiles, dict):
        if profile is not None:
            section = profiles.get(profile)
            if not isinstance(section, dict):
                available = ", ".join(sorted(profiles)) or "(none)"
                raise ConfigError(
                    f"Profile '{profile}' not found in {path}. Available: {available}."
                )
            return section
        default = profiles.get("default")
        if isinstance(default, dict):
            return default
        raise ConfigError(
            f"{path} defines named profiles; choose one with --profile "
            f"(available: {', '.join(sorted(profiles)) or '(none)'})."
        )

    if profile is not None:
        raise ConfigError(
            f"--profile {profile} given but {path} has no 'profiles:' section."
        )
    return raw
