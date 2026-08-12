"""Unit tests for guard.adapters hook-payload -> Action mapping."""

from __future__ import annotations

from guard.adapters import TARGETS, adapter_script, make_action


def test_claude_code_bash_payload_maps_to_shell() -> None:
    payload = {
        "session_id": "abc",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /", "description": "cleanup"},
        "cwd": "/repo",
    }
    action = make_action("claude-code", payload)
    assert action.type == "shell"
    assert action.command == "rm -rf /"
    assert action.cwd == "/repo"
    assert action.source == "Bash"


def test_cursor_shell_payload_maps_to_shell() -> None:
    payload = {
        "event": {"tool_name": "Shell", "tool_input": {"command": "echo hi"}},
        "hook": {"hookEventName": "preToolUse"},
    }
    action = make_action("cursor", payload)
    assert action.type == "shell"
    assert action.command == "echo hi"


def test_cursor_write_payload_maps_to_file() -> None:
    payload = {
        "event": {
            "tool_name": "Write",
            "tool_input": {"file_path": "/repo/new.txt", "content": "hello"},
        }
    }
    action = make_action("cursor", payload)
    assert action.type == "file"
    assert action.path == "/repo/new.txt"


def test_cursor_mcp_payload_maps_to_mcp() -> None:
    payload = {
        "event": {
            "tool_name": "mcp__filesystem__write_file",
            "tool_input": {"path": "/data/x.txt", "content": "abc"},
        }
    }
    action = make_action("cursor", payload)
    assert action.type == "mcp"
    assert action.tool == "mcp__filesystem__write_file"
    assert action.tool_args == {"path": "/data/x.txt", "content": "abc"}


def test_kiro_execute_bash_payload_maps_to_shell() -> None:
    payload = {"tool_name": "execute_bash", "tool_input": {"command": "whoami"}}
    action = make_action("kiro", payload)
    assert action.type == "shell"
    assert action.command == "whoami"


def test_kiro_fs_write_payload_maps_to_file() -> None:
    payload = {"tool_name": "fs_write", "tool_input": {"file_path": "/tmp/a.txt"}}
    action = make_action("kiro", payload)
    assert action.type == "file"
    assert action.path == "/tmp/a.txt"


def test_git_tool_maps_to_git_type() -> None:
    action = make_action(
        "claude-code", {"tool_name": "Git", "tool_input": {"command": "push --force"}}
    )
    assert action.type == "git"
    assert action.command == "push --force"


def test_empty_payload_falls_back_safely() -> None:
    action = make_action("cursor", {})
    assert action.type == "shell"
    assert action.command is None


def test_adapter_script_contains_target_and_fail_open() -> None:
    script = adapter_script("claude-code")
    assert 'TARGET = "claude-code"' in script
    assert "AGENT_ACTION_GUARD_URL" in script
    assert "Fail-open" in script


def test_adapter_script_targets_and_default_url() -> None:
    assert TARGETS == ("claude-code", "cursor", "kiro")
    script = adapter_script("cursor", default_url="http://127.0.0.1:9099")
    assert '"http://127.0.0.1:9099"' in script


def test_make_action_accepts_kiro_target() -> None:
    payload = {"tool_name": "execute_bash", "tool_input": {"command": "ls"}}
    assert make_action("kiro", payload) == make_action("claude-code", payload)
