"""Tests for guard.audit JSONL logging and markdown reports."""

from __future__ import annotations

import json

from guard.audit import AuditLog, render_markdown


def test_append_writes_jsonl_line(tmp_path, sample_decision_dict) -> None:
    log_path = tmp_path / "guard.jsonl"
    audit = AuditLog(log_path)
    audit.append(sample_decision_dict)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["verdict"] == "block"
    assert record["action_hash"] == sample_decision_dict["action_hash"]
    assert record["rule_id"] == "shell-rm-rf"
    assert "timestamp" in record
    assert record["action"]["type"] == "shell"


def test_append_multiple_entries(tmp_path, sample_decision_dict) -> None:
    log_path = tmp_path / "guard.jsonl"
    audit = AuditLog(log_path)

    allow_record = {
        **sample_decision_dict,
        "verdict": "allow",
        "reason": "no rules matched",
        "confidence": 0.95,
        "rule_id": None,
        "action": {"type": "shell", "command": "echo hi", "args": [], "cwd": "."},
    }
    audit.append(sample_decision_dict)
    audit.append(allow_record)

    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 2
    assert entries[0]["verdict"] == "block"
    assert entries[1]["verdict"] == "allow"


def test_render_markdown_empty_log(tmp_path) -> None:
    log_path = tmp_path / "empty.jsonl"
    log_path.write_text("", encoding="utf-8")
    report = render_markdown(log_path)
    assert "# Agent Action Guard — Audit Report" in report
    assert "_No audit entries recorded._" in report


def test_render_markdown_includes_counts_and_rules(tmp_path, sample_decision_dict) -> None:
    log_path = tmp_path / "guard.jsonl"
    audit = AuditLog(log_path)
    audit.append(sample_decision_dict)
    warn_record = {
        **sample_decision_dict,
        "verdict": "warn",
        "reason": "Broad process kill",
        "confidence": 0.75,
        "rule_id": "shell-kill-processes",
        "action": {"type": "shell", "command": "pkill node", "args": [], "cwd": "."},
    }
    audit.append(warn_record)

    report = render_markdown(log_path)
    assert "## Verdict counts" in report
    assert "| block | 1 |" in report
    assert "| warn | 1 |" in report
    assert "## Rule hits" in report
    assert "| shell-rm-rf | 1 |" in report
    assert "## Recent decisions" in report
    assert "shell-kill-processes" in report
