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
* ``GET  /`` — local dashboard for launching scans and reviewing history.
* ``POST /scan``   — run a scan. Body is :class:`ScanRequest`; the response is
  the serialised :class:`~webscan.models.ScanReport` plus an optional
  AI-written ``summary`` string.
* ``GET/DELETE /api/history/{id}`` — retrieve or remove a local scan history item.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webscan.ai import AIAssistant, AIConfig, ai_available
from webscan.api import scan
from webscan.dashboard import DASHBOARD_HTML
from webscan.history import ScanHistory
from webscan.models import CONFIDENCE_ORDER, Confidence
from webscan.reporter import Reporter

# Optional serve extra. Imported at module level (not inside create_app) so the
# endpoint annotations resolve against this module's globals — FastAPI relies on
# ``typing.get_type_hints``, which only sees module-level names. The import is
# guarded so ``import webscan.server`` still succeeds without the extra.
try:  # pragma: no cover - import wiring
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse
except Exception:  # noqa: BLE001 - missing optional dep => names are None
    FastAPI = HTTPException = Request = HTMLResponse = None  # type: ignore[assignment,misc]

# Default bind address: localhost only. Surfacing this as constants keeps the
# CLI and the docs in agreement on the safe default.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_HISTORY_PATH = Path.home() / ".webscan" / "history.db"

# Hardening caps for the HTTP backend (CWE-400 / CWE-770). A single client must
# not be able to exhaust the server's memory or open a million concurrent scans
# by sending a huge JSON body or absurd concurrency/timeout values.
_MAX_BODY_BYTES = 64 * 1024  # 64 KiB — request bodies are tiny (a list of URLs).
_MAX_TARGETS = 50
_MAX_TIMEOUT = 60
_MAX_CONCURRENCY = 32


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

    Hardening caps (CWE-400 / CWE-770) clamp ``targets`` / ``timeout`` /
    ``concurrency`` to sane bounds so a single client cannot exhaust the
    server by requesting ``concurrency=100000`` or scanning 1M targets at once.
    """
    targets = payload.get("targets") or []
    if not isinstance(targets, list):
        raise ValueError("targets must be a list of URLs")
    if not targets:
        raise ValueError("at least one target is required")
    if len(targets) > _MAX_TARGETS:
        raise ValueError(f"too many targets (max {_MAX_TARGETS})")

    # Clamp user-supplied ints to safe bounds. A bad type yields ValueError,
    # which the HTTP layer maps to a 400.
    try:
        timeout = int(payload.get("timeout", 10))
        concurrency = int(payload.get("concurrency", 10))
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout and concurrency must be integers") from exc
    timeout = max(1, min(timeout, _MAX_TIMEOUT))
    concurrency = max(1, min(concurrency, _MAX_CONCURRENCY))

    plugins = payload.get("plugins")
    if plugins is not None and not isinstance(plugins, list):
        raise ValueError("plugins must be a list of plugin names")

    report = await scan(
        targets,
        plugins=plugins,
        soft_404=bool(payload.get("soft_404", False)),
        bruteforce=bool(payload.get("bruteforce", True)),
        timeout=timeout,
        concurrency=concurrency,
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


def create_app(history_path: str | Path | None = None) -> FastAPI:
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
        version="2.8.0",
        description="Local HTTP backend for the WebScan security scanner.",
    )
    # Programmatic app instances default to an in-memory history so tests and
    # embedded users do not unexpectedly write to their home directory.
    history = ScanHistory(history_path or ":memory:")
    app.state.history = history

    @app.get("/", response_class=HTMLResponse)  # type: ignore
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(DASHBOARD_HTML)

    # Explicit CORS deny-all: a browser front-end on a different origin must
    # NOT be able to drive scans through this backend.
    try:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=[],
            allow_methods=[],
            allow_headers=[],
            allow_credentials=False,
        )
    except ImportError:  # pragma: no cover - defensive
        pass

    @app.get("/health")  # type: ignore
    async def health() -> dict[str, Any]:
        return {"status": "ok", "ai": ai_available()}

    @app.post("/scan")  # type: ignore
    async def scan_endpoint(request: Request) -> dict[str, Any]:
        # Parse the body ourselves rather than via a pydantic model: the model
        # would have to live at import time (pydantic is optional) and a
        # locally-defined one is unresolvable under ``from __future__ import
        # annotations``. run_scan validates and raises ValueError on bad input.
        # Body-size cap (CWE-400): read at most _MAX_BODY_BYTES; a larger body
        # is rejected with 413 before it can exhaust memory.
        raw = await request.body()
        if len(raw) > _MAX_BODY_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"request body too large (max {_MAX_BODY_BYTES} bytes)",
            )
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:  # malformed JSON body
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        try:
            result = await run_scan(payload)
            result["history_id"] = history.add(result["report"], result["summary"])
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/history")  # type: ignore
    async def history_list() -> list[dict[str, Any]]:
        return history.list()

    @app.get("/api/history/{scan_id}")  # type: ignore
    async def history_item(scan_id: int) -> dict[str, Any]:
        item = history.get(scan_id)
        if item is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return item

    @app.delete("/api/history/{scan_id}")  # type: ignore
    async def history_delete(scan_id: int) -> dict[str, bool]:
        if not history.delete(scan_id):
            raise HTTPException(status_code=404, detail="scan not found")
        return {"deleted": True}

    return app


def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    history_path: str | Path = DEFAULT_HISTORY_PATH,
) -> None:
    """Start the uvicorn server. Blocks until interrupted.

    :raises RuntimeError: if the ``serve`` extra is not installed.
    """
    if not server_available():
        raise RuntimeError(
            "The 'serve' extra is not installed. Run: "
            "pip install 'webscan-security[serve]'"
        )
    import uvicorn

    try:
        app = create_app(history_path)
    except OSError as exc:
        raise RuntimeError(f"Cannot open history database at {history_path}: {exc}") from exc
    uvicorn.run(app, host=host, port=port)
