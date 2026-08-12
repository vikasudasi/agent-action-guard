"""Tests for cli.main Typer commands via CliRunner."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from cli.main import app
from guard import __version__

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_check_allow_benign_action() -> None:
    action = json.dumps({"type": "shell", "command": "echo hi"})
    result = runner.invoke(app, ["check", "--action", action])
    assert result.exit_code == 0
    assert "allow" in result.stdout
    assert "no rules matched" in result.stdout


def test_check_block_dangerous_action() -> None:
    action = json.dumps({"type": "shell", "command": "rm -rf /"})
    result = runner.invoke(app, ["check", "--action", action])
    assert result.exit_code == 0
    assert "block" in result.stdout
    assert "shell-rm-rf" in result.stdout


def test_check_no_classifier_flag() -> None:
    action = json.dumps({"type": "shell", "command": "echo hi"})
    result = runner.invoke(app, ["check", "--action", action, "--no-classifier"])
    assert result.exit_code == 0
    assert "0.50" in result.stdout


def test_audit_renders_markdown(tmp_path) -> None:
    log_path = tmp_path / "guard.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-12T12:00:00+00:00",
                "action_hash": "abc",
                "verdict": "allow",
                "reason": "no rules matched",
                "confidence": 0.95,
                "rule_id": None,
                "action": {"type": "shell", "command": "echo hi"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["audit", "--log", str(log_path)])
    assert result.exit_code == 0
    assert "Audit Report" in result.stdout


def test_bench_runs_on_dataset(tmp_path) -> None:
    output = tmp_path / "bench_report.json"
    result = runner.invoke(app, ["bench", "--output", str(output)])
    assert result.exit_code == 0
    assert "Bench Report" in result.stdout
    assert output.exists()
