"""Tests for guard.server FastAPI endpoints (offline, no bound port)."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from guard.audit import AuditLog
from guard.schema import Action
from guard.server import create_app


@pytest.fixture
def client(tmp_path) -> TestClient:
    audit = AuditLog(tmp_path / "server.jsonl")
    app = create_app(audit_log=audit)
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestCheckEndpoint:
    def test_check_allow_benign_action(self, client: TestClient) -> None:
        payload = {"type": "shell", "command": "echo hi"}
        response = client.post("/check", json=payload)
        assert response.status_code == 200
        body = response.json()
        assert body["verdict"] == "allow"
        assert body["reason"] == "no rules matched"
        assert 0.0 <= body["confidence"] <= 1.0
        assert body["action_hash"] == Action.model_validate(payload).to_hash()

    def test_check_block_dangerous_action(self, client: TestClient) -> None:
        payload = {"type": "shell", "command": "rm -rf /"}
        response = client.post("/check", json=payload)
        assert response.status_code == 200
        body = response.json()
        assert body["verdict"] == "block"
        assert "Recursive force delete" in body["reason"] or "rm" in body["reason"].lower()
        assert body["confidence"] >= 0.85

    def test_check_malformed_body_returns_400(self, client: TestClient) -> None:
        response = client.post("/check", json={"command": "missing type"})
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert isinstance(detail, list)
        assert any("type" in str(item).lower() for item in detail)

    def test_check_writes_audit_log(self, client: TestClient, tmp_path) -> None:
        log_path = tmp_path / "server.jsonl"
        audit = AuditLog(log_path)
        app = create_app(audit_log=audit)
        test_client = TestClient(app)
        test_client.post("/check", json={"type": "shell", "command": "echo audited"})
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["verdict"] == "allow"
        assert record["action"]["command"] == "echo audited"


class TestEventsEndpoint:
    def test_events_stream_returns_event_stream_content_type(self, client: TestClient) -> None:
        # /events is an infinite SSE stream that only terminates on disconnect,
        # so it can't be drained to EOF in an offline test. Verify the route is
        # registered and its endpoint builds a StreamingResponse with the SSE
        # media type — which FastAPI resolves from the DefaultPlaceholder.
        import asyncio

        from fastapi.responses import StreamingResponse
        from fastapi.routing import APIRoute

        app = client.app  # type: ignore[assignment]
        route = next(
            (r for r in app.routes if isinstance(r, APIRoute) and r.path == "/events"),
            None,
        )
        assert route is not None, "/events route not registered"
        response = asyncio.run(route.endpoint())
        assert isinstance(response, StreamingResponse)
        assert response.media_type == "text/event-stream"
