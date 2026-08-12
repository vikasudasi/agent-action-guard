"""FastAPI serve endpoint with SSE verdict streaming."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import guard
from guard.audit import AuditLog
from guard.schema import Action

try:
    from fastapi import FastAPI, Request
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse, StreamingResponse
except ImportError as exc:  # pragma: no cover - optional serve extra
    raise ImportError(
        "FastAPI is required for the serve endpoint. Install with: pip install -e '.[serve]'"
    ) from exc


class EventBroker:
    """In-memory pub/sub broker for SSE verdict events."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: dict[str, Any]) -> None:
        async with self._lock:
            dead: list[asyncio.Queue[dict[str, Any]]] = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(queue)
            for queue in dead:
                self._subscribers.discard(queue)

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            async with self._lock:
                self._subscribers.discard(queue)


def _decision_response(decision: guard.Decision) -> dict[str, Any]:
    return {
        "verdict": decision.verdict,
        "reason": decision.reason,
        "confidence": decision.confidence,
        "action_hash": decision.action_hash,
    }


def _audit_record(decision: guard.Decision, action: Action) -> dict[str, Any]:
    return {
        "action_hash": decision.action_hash,
        "verdict": decision.verdict,
        "reason": decision.reason,
        "confidence": decision.confidence,
        "rule_id": decision.rule_id,
        "action": action.model_dump(mode="json"),
    }


def create_app(*, audit_log: AuditLog | None = None) -> FastAPI:
    """Build the FastAPI application wired to audit logging and SSE events."""
    broker = EventBroker()
    audit = audit_log or AuditLog("guard.jsonl")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.broker = broker
        app.state.audit = audit
        yield

    app = FastAPI(title="agent-action-guard", lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": exc.errors()})

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/check")
    async def check(action: Action) -> dict[str, Any]:
        decision = guard.evaluate(action)
        audit.append(_audit_record(decision, action))
        response = _decision_response(decision)
        await broker.publish(response)
        return response

    @app.get("/events")
    async def events() -> StreamingResponse:
        async def event_stream() -> AsyncIterator[str]:
            async for payload in broker.subscribe():
                data = json.dumps(payload, sort_keys=True)
                yield f"data: {data}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app
