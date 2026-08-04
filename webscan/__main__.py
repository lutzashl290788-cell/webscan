"""Allow the scanner to be launched as ``python -m webscan``.

Mirrors the ``webscan`` console script declared in ``pyproject.toml`` so the
package works without an installed entry point (e.g. from a source checkout).
"""
from __future__ import annotations

from webscan.cli import main

if __name__ == "__main__":
    main()
