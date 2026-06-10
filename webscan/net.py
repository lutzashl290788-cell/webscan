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
    random_delay: bool = False  # jitter the delay by ×0.5–×1.5
    rate_limit: float = 0.0  # max requests per second (0 = unlimited)
    verify_ssl: bool = False  # security scanners skip cert verification by default

    def base_delay(self) -> float:
        """Per-target delay before jitter: max of ``delay`` and the rate-limit gap."""
        base = self.delay
        if self.rate_limit > 0:
            base = max(base, 1.0 / self.rate_limit)
        return base

    def effective_delay(self, jitter: float) -> float:
        """Resolve the per-target delay, applying jitter and rate limiting.

        :param jitter: A factor in [0, 1) used to scale the base delay to
                       ×0.5–×1.5 when ``random_delay`` is set. Passed in (rather
                       than generated here) so callers stay deterministic/testable.
        """
        base = self.base_delay()
        if self.random_delay and base > 0:
            base = base * (0.5 + jitter)
        return base


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
