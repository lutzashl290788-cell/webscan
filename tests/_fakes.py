"""Lightweight fake aiohttp session/response for plugin unit tests.

Avoids a real HTTP server and the aioresponses/aiohttp version coupling.
Plugins only need ``session.get``/``session.options`` as async context
managers whose response exposes ``status``, ``headers`` and ``await text()``.
"""
from __future__ import annotations


class FakeHeaders:
    """Minimal case-insensitive multi-value header store."""

    def __init__(self, items: list[tuple[str, str]] | None = None) -> None:
        self._items: list[tuple[str, str]] = list(items or [])

    def get(self, key: str, default: str = "") -> str:
        for k, v in self._items:
            if k.lower() == key.lower():
                return v
        return default

    def getall(self, key: str, default: list[str] | None = None) -> list[str]:
        values = [v for k, v in self._items if k.lower() == key.lower()]
        if values:
            return values
        return [] if default is None else default

    def __getitem__(self, key: str) -> str:
        for k, v in self._items:
            if k.lower() == key.lower():
                return v
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return any(k.lower() == key.lower() for k, _ in self._items)

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        body: str = "",
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self.headers = FakeHeaders(headers)

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kwargs: object) -> str:
        return self._body


class FakeSession:
    """Returns one canned response for every verb and records the requests made."""

    def __init__(self, response: FakeResponse) -> None:
        self._response = response
        self.requests: list[tuple[str, str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        return self._response

    def options(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("OPTIONS", url, kwargs))
        return self._response

    def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("POST", url, kwargs))
        return self._response
