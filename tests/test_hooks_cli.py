"""CLI and end-to-end smoke tests for `agent-action-guard hooks install`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from cli.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()

DANGEROUS_SHELL = {"type": "shell", "command": "rm -rf /"}


def _claude_payload(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/repo"}


def _run_script(script: Path, payload: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_hooks_install_rejects_unknown_target(tmp_path: Path) -> None:
    result = runner.invoke(app, ["hooks", "install", "--target", "nope", "--dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "unknown target" in result.stderr


def test_hooks_install_claude_code_writes_config_and_adapter(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["hooks", "install", "--target", "claude-code", "--dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    config = tmp_path / ".claude" / "settings.json"
    script = tmp_path / "hooks" / "agent-action-guard-claude-code.py"
    assert config.exists()
    assert script.exists()

    data = json.loads(config.read_text(encoding="utf-8"))
    hook = data["hooks"]["PreToolUse"][0]
    assert hook["matcher"] == "Bash"
    assert hook["hooks"][0]["command"] == str(script)

    # Dangerous Bash payload -> expressive deny JSON, exit 0.
    proc = _run_script(script, _claude_payload("rm -rf /"))
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert "permissionDecisionReason" in out["hookSpecificOutput"]

    # Benign payload -> allow, no decision JSON on stdout.
    benign = _run_script(script, _claude_payload("echo hi"))
    assert benign.returncode == 0
    assert benign.stdout.strip() == ""


def test_hooks_install_cursor_writes_config_and_adapter(tmp_path: Path) -> None:
    result = runner.invoke(app, ["hooks", "install", "--target", "cursor", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    config = tmp_path / "hooks.json"
    script = tmp_path / "hooks" / "agent-action-guard-cursor.py"
    assert config.exists()

    data = json.loads(config.read_text(encoding="utf-8"))
    hook = data["hooks"]["preToolUse"][0]
    assert hook["matcher"] == "Shell|Write|MCP"

    payload = {"event": {"tool_name": "Shell", "tool_input": {"command": "rm -rf /"}}}
    proc = _run_script(script, payload)
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hooks_install_kiro_writes_config_and_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["hooks", "install", "--target", "kiro", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    config = tmp_path / ".kiro" / "hooks" / "guard.json"
    script = tmp_path / "hooks" / "agent-action-guard-kiro.py"
    assert config.exists()

    data = json.loads(config.read_text(encoding="utf-8"))
    hook = data["PreToolUse"][0]
    assert hook["matchers"] == ["execute_bash", "fs_write"]

    payload = {"tool_name": "execute_bash", "tool_input": {"command": "rm -rf /"}}
    proc = _run_script(script, payload)
    assert proc.returncode == 2
    assert "blocked action" in proc.stderr

    benign = _run_script(
        script, {"tool_name": "execute_bash", "tool_input": {"command": "echo hi"}}
    )
    assert benign.returncode == 0
