"""Shared pytest fixtures for agent-action-guard."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def allowlist_yaml(tmp_path: Path) -> Path:
    """YAML allowlist that downgrades scoped ``rm -rf /tmp/build``."""
    path = tmp_path / "allowlist.yaml"
    path.write_text(
        "rules:\n  - shell-rm-rf\ncommands:\n  - rm -rf /tmp/build\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def sample_decision_dict() -> dict[str, object]:
    """Minimal audit record payload."""
    return {
        "action_hash": "abc123" * 10 + "abcd",
        "verdict": "block",
        "reason": "Recursive force delete: Avoid `rm -rf`.",
        "confidence": 0.95,
        "rule_id": "shell-rm-rf",
        "action": {"type": "shell", "command": "rm -rf /", "args": [], "cwd": "."},
    }
