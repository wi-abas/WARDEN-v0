"""Tool specs: per-tool argument lists close the "argument nobody checks" gap."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from warden.api import create_app
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, ToolSpec
from warden.policy import Policy, load_policy

POLICY = {
    "tools": {"send_email": {"arguments": ["to", "subject", "body"], "required": ["to"]}},
    "rules": [
        {"id": "allow-email", "tool": "send_email", "effect": "allow"},
        {
            "id": "block-evil",
            "tool": "send_email",
            "effect": "deny",
            "when": [{"arg": "to", "op": "startswith", "value": "evil"}],
        },
        {"id": "allow-read", "tool": "read_file", "effect": "allow"},
    ],
}
CANARY = "sk-live-FAKE-123"  # fake secret used to detect leaks


def policy() -> Policy:
    return Policy.model_validate_json(json.dumps(POLICY))


def ask(tool: str = "send_email", **arguments: object):
    request = ActionRequest.model_validate({"agent_id": "a", "tool": tool, "arguments": arguments})
    p = policy()
    return evaluate(request, p.rules, p.tools)


# --- Behaviour -------------------------------------------------------------------------


def test_listed_arguments_follow_the_rules() -> None:
    assert ask(to="bob", subject="hi").decision == Decision.ALLOW
    assert ask(to="evil@x.y").decision == Decision.DENY


def test_the_bcc_trick_is_denied() -> None:
    result = ask(to="bob", bcc="evil@hacker.com")
    assert result.decision == Decision.DENY
    assert result.reason == "unexpected argument"
    assert result.action_hash is not None


def test_missing_required_argument_is_denied() -> None:
    result = ask(subject="hi")
    assert (result.decision, result.reason) == (Decision.DENY, "missing required argument 'to'")


def test_optional_argument_may_be_left_out() -> None:
    assert ask(to="bob").decision == Decision.ALLOW


def test_tools_without_a_spec_work_as_before() -> None:
    assert ask("read_file", path="/x", anything="goes").decision == Decision.ALLOW


def test_unexpected_argument_name_is_never_echoed() -> None:
    result = ask(to="bob", **{CANARY: "x"})
    assert CANARY not in result.model_dump_json()


def test_spec_check_runs_before_rules_even_for_deny_tools() -> None:
    # Unknown argument on an otherwise-allowed call: still denied, no rule involved.
    assert ask(to="bob", extra=1).matched_rule is None


def test_api_uses_the_tool_specs(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY))
    client = TestClient(create_app(path))
    body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "bob", "bcc": "x"}}
    assert client.post("/v1/evaluate", json=body).json()["decision"] == "deny"


# --- Validation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        {"arguments": ["to", "to"]},  # duplicate
        {"arguments": ["to"], "required": ["cc"]},  # required but not listed
        {"arguments": ["bad name!"]},
        {"arguments": "to"},  # not a list
        {"arguments": ["to"], "extra": True},  # unknown field
        {"required": ["to"]},  # arguments missing
    ],
)
def test_invalid_specs_are_rejected(spec: dict) -> None:
    with pytest.raises(ValidationError):
        ToolSpec.model_validate_json(json.dumps(spec))


def test_invalid_tool_name_in_specs_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate_json(
            json.dumps({"tools": {"Bad Tool": {"arguments": []}}, "rules": []})
        )


def test_bad_spec_in_file_loads_an_empty_policy(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    bad = {**POLICY, "tools": {"send_email": {"arguments": ["to"], "required": ["cc"]}}}
    path.write_text(json.dumps(bad))
    loaded = load_policy(path)
    assert loaded.rules == () and loaded.tools == {}


def test_policy_without_tools_still_loads(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": POLICY["rules"]}))
    assert len(load_policy(path).rules) == 3


def test_empty_argument_list_means_no_arguments_allowed() -> None:
    p = Policy.model_validate_json(
        json.dumps(
            {
                "tools": {"ping": {"arguments": []}},
                "rules": [{"id": "r", "tool": "ping", "effect": "allow"}],
            }
        )
    )
    req = ActionRequest.model_validate({"agent_id": "a", "tool": "ping", "arguments": {"x": 1}})
    assert evaluate(req, p.rules, p.tools).decision == Decision.DENY
    req = ActionRequest.model_validate({"agent_id": "a", "tool": "ping"})
    assert evaluate(req, p.rules, p.tools).decision == Decision.ALLOW
