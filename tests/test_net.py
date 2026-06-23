"""Tests for the network option helpers."""
from __future__ import annotations

from webscan.net import USER_AGENTS, NetConfig, pick_user_agent


def test_explicit_user_agent_wins() -> None:
    cfg = NetConfig(user_agent="Custom/1.0", random_agent=True)
    assert pick_user_agent(cfg, 3, "Default/1.0") == "Custom/1.0"


def test_random_agent_rotates_deterministically() -> None:
    cfg = NetConfig(random_agent=True)
    first = pick_user_agent(cfg, 0, "Default")
    same = pick_user_agent(cfg, 0, "Default")
    wrapped = pick_user_agent(cfg, len(USER_AGENTS), "Default")
    assert first in USER_AGENTS
    assert first == same == wrapped  # index-based, reproducible


def test_default_when_unconfigured() -> None:
    cfg = NetConfig()
    assert pick_user_agent(cfg, 5, "Default/1.0") == "Default/1.0"


def test_rate_limit_sets_minimum_delay() -> None:
    cfg = NetConfig(rate_limit=2.0)  # 2 req/s → 0.5s min gap
    assert cfg.base_delay() == 0.5


def test_delay_wins_over_rate_limit_when_larger() -> None:
    cfg = NetConfig(delay=1.0, rate_limit=10.0)  # rate gap 0.1 < delay 1.0
    assert cfg.base_delay() == 1.0


def test_random_delay_scales_within_bounds() -> None:
    cfg = NetConfig(delay=1.0, random_delay=True)
    assert cfg.effective_delay(0.0) == 0.5   # ×0.5 lower bound
    assert cfg.effective_delay(0.999) < 1.5  # below ×1.5 upper bound


def test_no_jitter_without_random_delay() -> None:
    cfg = NetConfig(delay=1.0)
    assert cfg.effective_delay(0.7) == 1.0
