"""agent-action-guard — action-safety decision layer for AI agents."""

from guard.decision import Decision, Verdict
from guard.rules import evaluate_with_allowlist
from guard.schema import Action

__version__ = "0.1.0"

__all__ = [
    "Action",
    "Decision",
    "Verdict",
    "__version__",
    "evaluate",
    "evaluate_with_allowlist",
]


def evaluate(action: Action) -> Decision:
    """Evaluate an action through the deterministic rule engine."""
    return evaluate_with_allowlist(action, None)
