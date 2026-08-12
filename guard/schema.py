"""Pydantic Action model — single source of truth for proposed agent actions."""

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field


class Action(BaseModel):
    """A proposed tool/action call from an AI agent."""

    type: Literal["shell", "file", "network", "mcp", "git"]
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    path: str | None = None
    url: str | None = None
    method: str | None = None
    tool: str | None = None
    tool_args: dict[str, Any] | None = None
    cwd: str = "."
    source: str | None = None

    def to_hash(self) -> str:
        """Return a stable SHA-256 hex digest of the canonical JSON serialization."""
        payload = self.model_dump(mode="json")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
