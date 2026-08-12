"""JSONL audit log writer and markdown report generator."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    """Append-only JSONL audit log for guard decisions."""

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)

    def append(self, decision: dict[str, Any]) -> None:
        """Write one JSONL record with timestamp and decision fields."""
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action_hash": decision["action_hash"],
            "verdict": decision["verdict"],
            "reason": decision["reason"],
            "confidence": decision["confidence"],
            "rule_id": decision.get("rule_id"),
            "action": decision["action"],
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def _load_entries(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []

    entries: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            entries.append(json.loads(stripped))
    return entries


def render_markdown(log_path: str | Path) -> str:
    """Generate a markdown summary report from a JSONL audit log."""
    path = Path(log_path)
    entries = _load_entries(path)

    lines = [
        "# Agent Action Guard — Audit Report",
        "",
        f"**Log:** `{path}`",
        f"**Total decisions:** {len(entries)}",
        "",
    ]

    if not entries:
        lines.append("_No audit entries recorded._")
        return "\n".join(lines) + "\n"

    verdict_counts = Counter(entry.get("verdict", "unknown") for entry in entries)
    lines.extend(
        [
            "## Verdict counts",
            "",
            "| Verdict | Count |",
            "|---------|------:|",
        ]
    )
    for verdict in ("allow", "block", "warn"):
        if verdict_counts.get(verdict, 0):
            lines.append(f"| {verdict} | {verdict_counts[verdict]} |")
    for verdict, count in sorted(verdict_counts.items()):
        if verdict not in {"allow", "block", "warn"}:
            lines.append(f"| {verdict} | {count} |")

    rule_hits = Counter(entry["rule_id"] for entry in entries if entry.get("rule_id") is not None)
    lines.extend(["", "## Rule hits", ""])
    if rule_hits:
        lines.extend(
            [
                "| Rule ID | Hits |",
                "|---------|-----:|",
            ]
        )
        for rule_id, count in rule_hits.most_common():
            lines.append(f"| {rule_id} | {count} |")
    else:
        lines.append("_No rule hits recorded._")

    recent = entries[-10:]
    lines.extend(["", "## Recent decisions", ""])
    lines.extend(
        [
            "| Timestamp | Verdict | Rule | Confidence | Action hash | Reason |",
            "|-----------|---------|------|------------|-------------|--------|",
        ]
    )
    for entry in reversed(recent):
        timestamp = str(entry.get("timestamp", ""))
        verdict = str(entry.get("verdict", ""))
        rule_id = str(entry.get("rule_id") or "")
        confidence = entry.get("confidence", "")
        if isinstance(confidence, (int, float)):
            confidence_text = f"{confidence:.2f}"
        else:
            confidence_text = str(confidence)
        action_hash = str(entry.get("action_hash", ""))
        hash_display = f"`{action_hash[:12]}…`" if len(action_hash) > 12 else f"`{action_hash}`"
        reason = str(entry.get("reason", "")).replace("|", "\\|")
        lines.append(
            f"| {timestamp} | {verdict} | {rule_id} | {confidence_text} "
            f"| {hash_display} | {reason} |"
        )

    return "\n".join(lines) + "\n"
