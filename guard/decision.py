"""Verdict types and Decision dataclass for guard evaluations."""

from dataclasses import dataclass
from typing import Literal

Verdict = Literal["allow", "block", "warn"]


@dataclass
class Decision:
    """Structured result of evaluating a proposed action."""

    verdict: Verdict
    reason: str
    confidence: float
    action_hash: str
    rule_id: str | None
