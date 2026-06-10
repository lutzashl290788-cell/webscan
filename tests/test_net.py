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
