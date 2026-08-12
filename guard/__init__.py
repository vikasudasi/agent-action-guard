"""agent-action-guard — action-safety decision layer for AI agents."""

from guard.classifier import Classifier, RuleClassifierMerger, merge_decisions
from guard.decision import Decision, Verdict
from guard.rules import _apply_allowlist, load_allowlist, summarize
from guard.rules import evaluate as evaluate_rules
from guard.rules import evaluate_with_allowlist as evaluate_rules_only
from guard.schema import Action

__version__ = "0.1.0"

_default_classifier = Classifier()
_default_merger = RuleClassifierMerger()

__all__ = [
    "Action",
    "Classifier",
    "Decision",
    "RuleClassifierMerger",
    "Verdict",
    "__version__",
    "evaluate",
    "evaluate_with_allowlist",
    "load_allowlist",
    "merge_decisions",
    "summarize",
]


def evaluate(action: Action, *, use_classifier: bool = True) -> Decision:
    """Evaluate an action through rules and optional classifier merge."""
    return evaluate_with_allowlist(action, None, use_classifier=use_classifier)


def evaluate_with_allowlist(
    action: Action,
    allowlist_file: str | None = None,
    *,
    use_classifier: bool = True,
) -> Decision:
    """Evaluate with optional YAML allowlist and classifier confidence merge."""
    if not use_classifier:
        return evaluate_rules_only(action, allowlist_file)

    rule_decisions = evaluate_rules(action)
    if allowlist_file is not None:
        allowlist = load_allowlist(allowlist_file)
        rule_decisions = _apply_allowlist(rule_decisions, action, allowlist)

    score = _default_classifier.score(action)
    return _default_merger.merge(rule_decisions, action, score)
