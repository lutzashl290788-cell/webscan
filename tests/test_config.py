"""Tests for YAML config-file / profile loading and CLI precedence."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from webscan import cli
from webscan.config import ConfigError, load_profile


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "webscan.yml"
    path.write_text(text, encoding="utf-8")
    return path


def test_flat_config_filters_unknown_keys(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "concurrency: 25\nplugins: [headers]\nbogus: 9\n")
    profile = load_profile(cfg)
    assert profile == {"concurrency": 25, "plugins": ["headers"]}


def test_named_profile_selection(tmp_path: Path) -> None:
    cfg = _write(tmp_path, (
        "profiles:\n"
        "  quick:\n"
        "    plugins: [headers, cookies]\n"
        "    concurrency: 30\n"
        "  deep:\n"
        "    plugins: [xss]\n"
        "    crawl: true\n"
    ))
    assert load_profile(cfg, "quick") == {
        "plugins": ["headers", "cookies"],
        "concurrency": 30,
    }
    assert load_profile(cfg, "deep") == {"plugins": ["xss"], "crawl": True}


def test_default_profile_used_without_name(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  default:\n    timeout: 7\n")
    assert load_profile(cfg) == {"timeout": 7}


def test_unknown_profile_raises(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  quick:\n    timeout: 7\n")
    with pytest.raises(ConfigError):
        load_profile(cfg, "nope")


def test_named_profiles_without_selection_raises(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  quick:\n    timeout: 7\n")
    with pytest.raises(ConfigError):
        load_profile(cfg)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_profile(tmp_path / "absent.yml")


def test_empty_file_is_empty(tmp_path: Path) -> None:
    assert load_profile(_write(tmp_path, "")) == {}


# ── CLI precedence ─────────────────────────────────────────────────────────────

def test_cli_overrides_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _write(tmp_path, "concurrency: 25\nplugins: [headers]\n")
    argv = ["webscan", "-t", "https://x.test", "--config", str(cfg)]
    monkeypatch.setattr(sys, "argv", argv)

    parser = cli._build_parser()
    cli._apply_config(parser)

    # No explicit --concurrency: config value wins over the built-in default.
    args = parser.parse_args(argv[1:])
    assert args.concurrency == 25
    assert args.plugins == ["headers"]

    # Explicit flag beats the config value.
    args = parser.parse_args([*argv[1:], "--concurrency", "5"])
    assert args.concurrency == 5


# ── Coverage gaps ──────────────────────────────────────────────────────────────


def test_invalid_yaml_raises_config_error(tmp_path: Path) -> None:
    """Lines 82-83: malformed YAML triggers ConfigError."""
    cfg = _write(tmp_path, "concurrency: [unclosed\nlist")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_profile(cfg)


def test_non_mapping_root_raises_config_error(tmp_path: Path) -> None:
    """Line 88: a YAML scalar (not a mapping) at root triggers ConfigError."""
    cfg = _write(tmp_path, "just a string, not a mapping")
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_profile(cfg)


def test_profile_flag_without_profiles_section_raises(tmp_path: Path) -> None:
    """Line 117: --profile given but file has no 'profiles:' section."""
    cfg = _write(tmp_path, "plugins: [headers]\n")
    with pytest.raises(ConfigError, match="has no 'profiles:'"):
        load_profile(cfg, "quick")
