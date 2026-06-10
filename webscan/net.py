"""Networking options: proxy, User-Agent rotation and request pacing."""
from __future__ import annotations

from dataclasses import dataclass

# A small, realistic pool used by --random-agent. Kept short on purpose; the
# goal is light rotation, not a full fingerprint-evasion database.
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


@dataclass
class NetConfig:
    """Network-layer options shared by the crawler and scan engine."""

    proxy: str = ""  # e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050
    user_agent: str = ""  # explicit override; empty keeps the default
    random_agent: bool = False
    delay: float = 0.0  # seconds to pace between dispatched targets


def pick_user_agent(config: NetConfig, index: int, default: str) -> str:
    """Return the User-Agent to use for the *index*-th unit of work.

    Precedence: explicit ``--user-agent`` > ``--random-agent`` rotation >
    *default*. Rotation is deterministic in *index* to stay reproducible.
    """
    if config.user_agent:
        return config.user_agent
    if config.random_agent:
        return USER_AGENTS[index % len(USER_AGENTS)]
    return default
