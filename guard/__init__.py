"""agent-action-guard — action-safety decision layer for AI agents."""

from guard.decision import Decision, Verdict
from guard.schema import Action

__version__ = "0.1.0"

__all__ = ["Action", "Decision", "Verdict", "__version__", "evaluate"]


def evaluate(action: Action) -> Decision:
    """Evaluate an action and return a verdict (stub until rules engine lands in Task 2)."""
    return Decision(
        verdict="allow",
        reason="no rules matched",
        confidence=0.5,
        action_hash=action.to_hash(),
        rule_id=None,
    )
