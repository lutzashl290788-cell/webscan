"""Asynchronous crawler/spider — expands a seed URL into a set of in-scope URLs.

Breadth-first traversal bounded by depth, URL count and domain scope, with
optional ``robots.txt`` compliance. Discovered forms are collected alongside
URLs so injection plugins can fuzz them later.
"""
from __future__ import annotations

import asyncio
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
    concurrency: int = 10  # max simultaneous page fetches per depth level


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
        """Crawl outward from *seed* and return discovered URLs and forms.

        Traversal is breadth-first, processed one depth level at a time. All
        pages in a level are fetched concurrently (bounded by
        ``config.concurrency``), which is far faster than the serial
        URL-at-a-time walk while preserving identical depth/scope/robots/cap
        semantics.
        """
        scope = self.config.scope or urlparse(seed).netloc
        result = CrawlResult()
        visited: set[str] = set()
        frontier: list[str] = [seed]
        depth = 0
        sem = asyncio.Semaphore(max(1, self.config.concurrency))

        if self.config.respect_robots:
            await self._load_robots(seed)

        while frontier and len(visited) < self.config.max_urls:
            # Admit this level's in-scope, unvisited, robots-allowed URLs,
            # honouring the global max-URL cap.
            current: list[str] = []
            for url in frontier:
                if len(visited) >= self.config.max_urls:
                    break
                if url in visited:
                    continue
                if not self._in_scope(url, scope) or self._excluded(url):
                    continue
                if not self._robots_allows(url):
                    continue
                visited.add(url)
                result.urls.append(url)
                current.append(url)

            if depth >= self.config.max_depth or not current:
                break

            async def _fetch(u: str) -> ParsedPage | None:
                async with sem:
                    return await self._fetch_and_parse(u)

            pages = await asyncio.gather(*(_fetch(u) for u in current))

            next_frontier: list[str] = []
            for url, page in zip(current, pages):
                if page is None:
                    continue
                if page.forms:
                    result.forms[url] = page.forms
                for link in page.links:
                    if link not in visited:
                        next_frontier.append(link)

            frontier = next_frontier
            depth += 1

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
                # Cap body size to bound memory (CWE-400). 2 MiB is plenty for
                # any HTML page worth crawling. Falls back to ``text()`` for
                # test fakes without a streaming body.
                try:
                    raw = await resp.content.read(2 * 1024 * 1024)
                    body = raw.decode("utf-8", errors="ignore")
                except (AttributeError, TypeError):
                    try:
                        body = await resp.text(errors="ignore")
                    except TypeError:
                        body = await resp.text()
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
                # Cap body size (CWE-400). robots.txt is small but a hostile
                # target could serve a multi-MB response.
                try:
                    raw = await resp.content.read(512 * 1024)
                    text = raw.decode("utf-8", errors="ignore")
                except (AttributeError, TypeError):
                    try:
                        text = await resp.text(errors="ignore")
                    except TypeError:
                        text = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return
        rp = RobotFileParser()
        rp.parse(text.splitlines())
        self._robots = rp

    def _robots_allows(self, url: str) -> bool:
        if self._robots is None:
            return True
        return self._robots.can_fetch("*", url)
