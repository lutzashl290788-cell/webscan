"""Abstract base class for all WebScan plugins."""
from __future__ import annotations

from abc import ABC, abstractmethod

import aiohttp

from webscan.models import Finding


class BasePlugin(ABC):
    """
    Every plugin must inherit from BasePlugin and implement :meth:`run`.

    Plugin discovery happens via ``ALL_PLUGINS`` in ``cli.py``.  To add a new
    plugin, create a module under ``webscan/plugins/``, subclass
    ``BasePlugin``, and register it.
    """

    #: Short machine-readable identifier (used in CLI --plugins flag).
    name: str = ""
    #: One-line human description shown by --list-plugins.
    description: str = ""

    @abstractmethod
    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        """
        Perform checks against *target* using the shared *session*.

        Must never raise — catch all exceptions internally and return an
        empty list (or a partial list) instead.

        :param target: Normalised target URL, e.g. ``https://example.com``.
        :param session: Shared ``aiohttp.ClientSession`` configured by the engine.
        :returns: List of :class:`~webscan.models.Finding` objects (may be empty).
        """
        ...
