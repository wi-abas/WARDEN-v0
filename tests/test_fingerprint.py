import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import create_app
from warden.engine import evaluate
from warden.fingerprint import fingerprint
from warden.models import ActionRequest, Decision, Rule


def action(
    agent_id: str = "finance-agent",
    tool: str = "send_invoice",
    **arguments: object,
) -> ActionRequest:
    if not arguments:
        arguments = {"recipient": "supplier@example.com", "amount": 500}
    return ActionRequest.model_validate(
        {"agent_id": agent_id, "tool": tool, "arguments": arguments}
    )


# --- Basic properties --------------------------------------------------------------


def test_fingerprint_is_64_hex_characters() -> None:
    value = fingerprint(action())
    assert len(value) == 64
    assert all(c in "0123456789abcdef" for c in value)


def test_known_value_never_changes_by_accident() -> None:
    # If this fails, the fingerprint format changed. That would invalidate every
    # stored approval, so it must only happen on purpose, with a new version label.
    assert fingerprint(action()) == (
        "9b3d34132ae3484d20e8c6503b84d436addc219faa249f58bbccd9e5822bdd82"
    )


def test_same_action_same_fingerprint() -> None:
    assert fingerprint(action()) == fingerprint(action())


def test_key_order_does_not_matter() -> None:
    a = action(recipient="x@y.z", amount=500, meta={"b": 1, "a": 2})
    b = action(meta={"a": 2, "b": 1}, amount=500, recipient="x@y.z")
    assert fingerprint(a) == fingerprint(b)


# --- Any change gives a different fingerprint --------------------------------------


@pytest.mark.parametrize(
    "changed",
    [
        action(recipient="supplier@example.com", amount=50000),  # €500 -> €50,000
        action(recipient="attacker@example.com", amount=500),  # different recipient
        action(recipient="supplier@example.com", amount="500"),  # number -> string
        action(recipient="supplier@example.com", amount=500, cc="x@y.z"),  # extra argument
        action(recipient="supplier@example.com"),  # argument removed
        action(tool="send_payment"),  # different tool
        action(agent_id="other-agent"),  # different agent
    ],
)
def test_any_change_changes_the_fingerprint(changed: ActionRequest) -> None:
    assert fingerprint(changed) != fingerprint(action())


# --- Wired into the engine and API --------------------------------------------------


@pytest.mark.parametrize("effect", list(Decision))
def test_engine_result_carries_the_fingerprint(effect: Decision) -> None:
    rules = [Rule(id="r1", tool="send_invoice", effect=effect)]
    result = evaluate(action(), rules)
    assert result.action_hash == fingerprint(action())


def test_no_match_deny_still_carries_the_fingerprint() -> None:
    assert evaluate(action(), []).action_hash == fingerprint(action())


def test_api_response_includes_the_fingerprint() -> None:
    client = TestClient(create_app(BASIC_POLICY))
    request = action(tool="send_email", to="a@b.c")
    response = client.post("/v1/evaluate", json=request.model_dump())
    assert response.json()["action_hash"] == fingerprint(request)
