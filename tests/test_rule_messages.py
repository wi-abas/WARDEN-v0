"""Custom rule messages: explain WHY, in the decision's reason."""

import json

import pytest
from pydantic import ValidationError

from warden.approvals import ApprovalStore, apply_approval
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule

MESSAGE = "Payments over €500 need finance approval"


def rule(**extra: object) -> Rule:
    base = {"id": "big", "tool": "pay", "effect": "require_approval"}
    return Rule.model_validate_json(json.dumps({**base, **extra}))


def pay() -> ActionRequest:
    return ActionRequest.model_validate({"agent_id": "a", "tool": "pay", "arguments": {}})


def test_message_becomes_the_reason() -> None:
    result = evaluate(pay(), [rule(message=MESSAGE)])
    assert result.reason == MESSAGE
    assert result.matched_rule == "big"


def test_without_message_the_reason_names_the_rule() -> None:
    assert evaluate(pay(), [rule()]).reason == "matched rule 'big'"


def test_approved_reason_keeps_the_message() -> None:
    store = ApprovalStore()
    first = apply_approval(pay(), evaluate(pay(), [rule(message=MESSAGE)]), store)
    assert first.approval_id is not None
    store.decide(first.approval_id, approve=True)
    retry = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "pay", "arguments": {}, "approval_id": first.approval_id}
    )
    final = apply_approval(retry, evaluate(retry, [rule(message=MESSAGE)]), store)
    assert final.decision == Decision.ALLOW
    assert final.reason == f"approved by a human ({MESSAGE})"


@pytest.mark.parametrize("bad", ["", "x" * 201, "line one\nline two", "tab\there", 5])
def test_bad_messages_rejected(bad: object) -> None:
    with pytest.raises(ValidationError):
        rule(message=bad)


def test_unicode_message_allowed() -> None:
    assert rule(message="Zahlungen über 500 € brauchen Freigabe").message is not None
