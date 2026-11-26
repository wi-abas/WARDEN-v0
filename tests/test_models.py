import pytest
from pydantic import ValidationError

from warden.models import MAX_ARGUMENTS, ActionRequest, Decision, EvaluationResult, Rule


def valid_request(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "agent_id": "agent-1",
        "tool": "read_file",
        "arguments": {"path": "notes.txt"},
    }
    data.update(overrides)
    return data


# --- Valid input ---------------------------------------------------------------


def test_valid_request_is_accepted() -> None:
    request = ActionRequest.model_validate(valid_request())
    assert request.tool == "read_file"
    assert request.arguments == {"path": "notes.txt"}


def test_arguments_default_to_empty() -> None:
    data = valid_request()
    del data["arguments"]
    assert ActionRequest.model_validate(data).arguments == {}


def test_valid_request_from_json() -> None:
    raw = '{"agent_id": "agent-1", "tool": "send_email", "arguments": {"to": "a@b.c"}}'
    assert ActionRequest.model_validate_json(raw).tool == "send_email"


# --- Rejected input ------------------------------------------------------------


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(valid_request(approved=True))


@pytest.mark.parametrize("field", ["agent_id", "tool"])
def test_missing_required_field_is_rejected(field: str) -> None:
    data = valid_request()
    del data[field]
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(data)


@pytest.mark.parametrize(
    "tool",
    [
        "",  # empty
        "delete_file ",  # trailing space
        " delete_file",  # leading space
        "delete file",  # space inside
        "delete_fіle",  # Cyrillic "і" that looks like a Latin "i"
        "delete_file\n",  # newline
        "../delete_file",  # slash
        "a" * 65,  # too long
    ],
)
def test_bad_tool_names_are_rejected(tool: str) -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(valid_request(tool=tool))


@pytest.mark.parametrize("tool", ["getIssue", "Delete_File", "GITHUB.createPR"])
def test_mixed_case_tool_names_are_accepted_as_written(tool: str) -> None:
    # MCP servers name tools in camelCase; kept exactly, never lower-cased.
    assert ActionRequest.model_validate(valid_request(tool=tool)).tool == tool


@pytest.mark.parametrize("agent_id", ["", "agent 1", "a" * 129])
def test_bad_agent_ids_are_rejected(agent_id: str) -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(valid_request(agent_id=agent_id))


def test_wrong_types_are_not_converted() -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(valid_request(tool=123))


def test_arguments_must_be_an_object() -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(valid_request(arguments=["not", "a", "dict"]))


def test_too_many_arguments_are_rejected() -> None:
    too_many = {f"k{i}": i for i in range(MAX_ARGUMENTS + 1)}
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(valid_request(arguments=too_many))


def test_request_cannot_be_modified_after_creation() -> None:
    request = ActionRequest.model_validate(valid_request())
    with pytest.raises(ValidationError):
        request.tool = "delete_file"  # type: ignore[misc]


# --- Decisions -----------------------------------------------------------------


def test_decision_values() -> None:
    assert {d.value for d in Decision} == {"allow", "deny", "require_approval"}


def test_unknown_decision_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EvaluationResult.model_validate_json('{"decision": "maybe", "reason": "x"}')


def test_result_serialises_to_plain_strings() -> None:
    result = EvaluationResult(decision=Decision.DENY, reason="no matching rule")
    assert result.model_dump(mode="json") == {
        "decision": "deny",
        "reason": "no matching rule",
        "matched_rule": None,
        "action_hash": None,
        "approval_id": None,
    }


# --- Rules ---------------------------------------------------------------------


def test_valid_rule_from_json() -> None:
    rule = Rule.model_validate_json('{"id": "allow-read", "tool": "read_file", "effect": "allow"}')
    assert rule.effect == Decision.ALLOW


@pytest.mark.parametrize(
    "raw",
    [
        '{"id": "r1", "tool": "read_file", "effect": "maybe"}',  # unknown effect
        '{"id": "r1", "tool": "Read File", "effect": "allow"}',  # bad tool name (space)
        '{"id": "Bad Id", "tool": "read_file", "effect": "allow"}',  # bad id
        '{"id": "r1", "tool": "read_file"}',  # missing effect
        '{"id": "r1", "tool": "read_file", "effect": "allow", "priority": 1}',  # extra field
    ],
)
def test_bad_rules_are_rejected(raw: str) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate_json(raw)
