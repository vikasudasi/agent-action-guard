"""Tests for guard.schema.Action parsing and hashing."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from guard import __version__, evaluate
from guard.schema import Action


def test_version_is_non_empty_string() -> None:
    assert isinstance(__version__, str)
    assert __version__


def test_action_minimal_shell() -> None:
    action = Action.model_validate({"type": "shell", "command": "echo hi"})
    assert action.type == "shell"
    assert action.command == "echo hi"
    assert action.args == []
    assert action.cwd == "."


def test_action_all_fields_round_trip() -> None:
    payload = {
        "type": "network",
        "url": "https://api.example.com/v1/data",
        "method": "POST",
        "cwd": "/app",
        "source": "cursor-agent",
    }
    action = Action.model_validate(payload)
    dumped = action.model_dump(mode="json")
    assert dumped["type"] == "network"
    assert dumped["url"] == payload["url"]
    assert dumped["method"] == "POST"
    assert dumped["cwd"] == "/app"
    assert dumped["source"] == "cursor-agent"


def test_action_invalid_type_rejected() -> None:
    with pytest.raises(ValidationError):
        Action.model_validate({"type": "email", "command": "send"})


def test_to_hash_is_stable() -> None:
    action = Action(type="shell", command="echo hi")
    assert action.to_hash() == action.to_hash()
    assert len(action.to_hash()) == 64


def test_to_hash_changes_when_payload_changes() -> None:
    a = Action(type="shell", command="echo hi")
    b = Action(type="shell", command="echo bye")
    assert a.to_hash() != b.to_hash()


def test_to_hash_matches_canonical_json_sha256() -> None:
    action = Action(type="file", path="README.md", args=["read"])
    payload = action.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    import hashlib

    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert action.to_hash() == expected


def test_evaluate_benign_echo_allow() -> None:
    action = Action(type="shell", command="echo hi")
    decision = evaluate(action)
    assert decision.verdict == "allow"
    assert decision.rule_id is None
    assert decision.action_hash == action.to_hash()
