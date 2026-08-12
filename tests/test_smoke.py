"""Minimal smoke tests so CI can run before the full test suite (Task 5)."""

from guard import __version__, evaluate
from guard.schema import Action


def test_version_is_string() -> None:
    assert isinstance(__version__, str)
    assert __version__


def test_action_import_and_hash() -> None:
    action = Action(type="shell", command="echo hi")
    h1 = action.to_hash()
    h2 = action.to_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_evaluate_stub_allow() -> None:
    action = Action(type="shell", command="echo hi")
    decision = evaluate(action)
    assert decision.verdict == "allow"
    assert decision.rule_id is None
