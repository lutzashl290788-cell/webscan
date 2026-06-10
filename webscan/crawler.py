"""Asynchronous crawler/spider — expands a seed URL into a set of in-scope URLs.

Breadth-first traversal bounded by depth, URL count and domain scope, with
optional ``robots.txt`` compliance. Discovered forms are collected alongside
URLs so injection plugins can fuzz them later.
"""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import aiohttp

from webscan.utils.html import Form, ParsedPage, parse_html

_HTML_CT = ("text/html", "application/xhtml")


@dataclass
class CrawlConfig:
    """Tunable limits for a crawl run."""

    max_depth: int = 2
    max_urls: int = 200
    scope: str = ""  # registrable host to stay within; defaults to seed host
    respect_robots: bool = True
    exclude: list[str] = field(default_factory=list)  # substrings to skip


@dataclass
class CrawlResult:
    """Everything the crawler discovered."""

    urls: list[str] = field(default_factory=list)
    forms: dict[str, list[Form]] = field(default_factory=dict)  # page URL -> forms


class Crawler:
    """Breadth-first async crawler sharing the engine's ``ClientSession``."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        config: CrawlConfig | None = None,
    ) -> None:
        self.session = session
        self.config = config or CrawlConfig()
        self._robots: RobotFileParser | None = None

    async def crawl(self, seed: str) -> CrawlResult:
        """Crawl outward from *seed* and return discovered URLs and forms."""
        scope = self.config.scope or urlparse(seed).netloc
        result = CrawlResult()
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(seed, 0)])

        if self.config.respect_robots:
            await self._load_robots(seed)

        while queue and len(visited) < self.config.max_urls:
            url, depth = queue.popleft()
            if url in visited:
                continue
            if not self._in_scope(url, scope) or self._excluded(url):
                continue
            if not self._robots_allows(url):
                continue

            visited.add(url)
            result.urls.append(url)

            if depth >= self.config.max_depth:
                continue

            page = await self._fetch_and_parse(url)
            if page is None:
                continue

            if page.forms:
                result.forms[url] = page.forms

            for link in page.links:
                if link not in visited:
                    queue.append((link, depth + 1))

        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch_and_parse(self, url: str) -> ParsedPage | None:
        try:
            async with self.session.get(url, ssl=False) as resp:
                ctype = resp.headers.get("Content-Type", "").lower()
                if not any(h in ctype for h in _HTML_CT):
                    return None
                body = await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None
        return parse_html(body, base=url)

    def _in_scope(self, url: str, scope: str) -> bool:
        host = urlparse(url).netloc
        return host == scope or host.endswith("." + scope)

    def _excluded(self, url: str) -> bool:
        return any(pattern in url for pattern in self.config.exclude)

    async def _load_robots(self, seed: str) -> None:
        parsed = urlparse(seed)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            async with self.session.get(robots_url, ssl=False) as resp:
                if resp.status != 200:
                    return
                text = await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return
        rp = RobotFileParser()
        rp.parse(text.splitlines())
        self._robots = rp

    def _robots_allows(self, url: str) -> bool:
        if self._robots is None:
            return True
        return self._robots.can_fetch("*", url)
