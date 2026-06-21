"""Optional HTTP backend for WebScan (``webscan serve``).

This module exposes a small, **opt-in** web API around the same scan engine the
CLI uses. It exists so a browser front-end (or any HTTP client) can launch a
scan and, optionally, have the results annotated by the Claude AI layer —
**without ever putting the Anthropic API key in the browser**. The key is read
from ``ANTHROPIC_API_KEY`` in the server process only; see :mod:`webscan.ai`.

Design rules (mirroring :mod:`webscan.ai`):

* ``fastapi`` / ``uvicorn`` are **optional** dependencies (``pip install
  webscan-security[serve]``). Importing this module never fails when they are
  missing — :func:`server_available` reports the truth and :func:`create_app`
  raises a clear error only if you actually try to build the app.
* The server binds to ``127.0.0.1`` by default. It is a local helper, not a
  hardened public service: do not expose it to the internet without your own
  authentication and rate limiting in front of it.
* The legal responsibility for scanning a target is the operator's, exactly as
  in the CLI. The API does not relax that.

Endpoints:

* ``GET  /health`` — liveness probe; also reports whether the AI layer is
  configured (SDK importable *and* a key present).
* ``POST /scan``   — run a scan. Body is :class:`ScanRequest`; the response is
  the serialised :class:`~webscan.models.ScanReport` plus an optional
  AI-written ``summary`` string.
"""
from __future__ import annotations

import json
from typing import Any

from webscan.ai import AIAssistant, AIConfig, ai_available
from webscan.api import scan
from webscan.models import CONFIDENCE_ORDER, Confidence
from webscan.reporter import Reporter

# Optional serve extra. Imported at module level (not inside create_app) so the
# endpoint annotations resolve against this module's globals — FastAPI relies on
# ``typing.get_type_hints``, which only sees module-level names. The import is
# guarded so ``import webscan.server`` still succeeds without the extra.
try:  # pragma: no cover - import wiring
    from fastapi import FastAPI, HTTPException, Request
except Exception:  # noqa: BLE001 - missing optional dep => names are None
    FastAPI = HTTPException = Request = None  # type: ignore[assignment,misc]

# Default bind address: localhost only. Surfacing this as constants keeps the
# CLI and the docs in agreement on the safe default.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def server_available() -> bool:
    """Return True only if both fastapi and uvicorn are importable. Never raises."""
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except Exception:  # noqa: BLE001 - missing/broken optional deps => unavailable
        return False
    return True


def _confidence_from_str(value: str | None) -> Confidence | None:
    """Map a confidence name to the enum, or None if unset/unknown."""
    if not value:
        return None
    try:
        conf = Confidence(value)
    except ValueError:
        return None
    return conf if conf in CONFIDENCE_ORDER else None


async def run_scan(payload: dict[str, Any]) -> dict[str, Any]:
    """Core request handler, framework-agnostic so it is trivially testable.

    Takes a plain dict (already validated by the caller), runs the scan, applies
    the optional AI layer, and returns a JSON-serialisable dict::

        {"report": {...}, "summary": "..."}

    AI is strictly best-effort: if the SDK or key is missing, or the API errors,
    ``summary`` is ``""`` and the report is returned unannotated.
    """
    targets = payload.get("targets") or []
    if not targets:
        raise ValueError("at least one target is required")

    report = await scan(
        targets,
        plugins=payload.get("plugins"),
        soft_404=bool(payload.get("soft_404", False)),
        bruteforce=bool(payload.get("bruteforce", True)),
        timeout=int(payload.get("timeout", 10)),
        concurrency=int(payload.get("concurrency", 10)),
        min_confidence=_confidence_from_str(payload.get("min_confidence")),
    )

    summary = ""
    want_triage = bool(payload.get("ai_triage", False))
    want_summary = bool(payload.get("ai_summary", False))
    if want_triage or want_summary:
        assistant = AIAssistant(config=AIConfig(model=str(payload.get("ai_model", ""))))
        if assistant.available:
            if want_triage:
                await assistant.triage_report(report)
            if want_summary:
                summary = await assistant.summarize_report(report)

    report_dict = json.loads(Reporter(report).to_json())
    return {"report": report_dict, "summary": summary}


def create_app() -> FastAPI:
    """Build and return the FastAPI application.

    :raises RuntimeError: if the ``serve`` extra (fastapi) is not installed.
    """
    if not server_available():
        raise RuntimeError(
            "The 'serve' extra is not installed. Run: "
            "pip install 'webscan-security[serve]'"
        )

    app = FastAPI(
        title="WebScan",
        version="2.0.0",
        description="Local HTTP backend for the WebScan security scanner.",
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "ai": ai_available()}

    @app.post("/scan")
    async def scan_endpoint(request: Request) -> dict[str, Any]:
        # Parse the body ourselves rather than via a pydantic model: the model
        # would have to live at import time (pydantic is optional) and a
        # locally-defined one is unresolvable under ``from __future__ import
        # annotations``. run_scan validates and raises ValueError on bad input.
        try:
            payload = await request.json()
        except Exception as exc:  # noqa: BLE001 - malformed JSON body
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        try:
            return await run_scan(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Start the uvicorn server. Blocks until interrupted.

    :raises RuntimeError: if the ``serve`` extra is not installed.
    """
    if not server_available():
        raise RuntimeError(
            "The 'serve' extra is not installed. Run: "
            "pip install 'webscan-security[serve]'"
        )
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)
