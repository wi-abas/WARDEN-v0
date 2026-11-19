import logging
from collections.abc import Iterator

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule

ALLOW = Decision.ALLOW
DENY = Decision.DENY
APPROVAL = Decision.REQUIRE_APPROVAL


def request(tool: str, **arguments: object) -> ActionRequest:
    return ActionRequest.model_validate(
        {"agent_id": "agent-1", "tool": tool, "arguments": arguments}
    )


def rule(rule_id: str, tool: str, effect: Decision) -> Rule:
    return Rule(id=rule_id, tool=tool, effect=effect)


STANDARD_RULES = [
    rule("allow-read", "read_file", ALLOW),
    rule("approve-send", "send_email", APPROVAL),
    rule("block-delete", "delete_file", DENY),
]


# --- Single matching rule --------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "decision", "rule_id"),
    [
        ("read_file", ALLOW, "allow-read"),
        ("send_email", APPROVAL, "approve-send"),
        ("delete_file", DENY, "block-delete"),
    ],
)
def test_matching_rule_decides(tool: str, decision: Decision, rule_id: str) -> None:
    result = evaluate(request(tool), STANDARD_RULES)
    assert result.decision == decision
    assert result.matched_rule == rule_id


# --- Default deny ------------------------------------------------------------------


def test_no_rules_means_deny() -> None:
    result = evaluate(request("read_file"), [])
    assert result.decision == DENY
    assert result.matched_rule is None


def test_unknown_tool_means_deny() -> None:
    result = evaluate(request("format_disk"), STANDARD_RULES)
    assert result.decision == DENY
    assert result.matched_rule is None
    assert result.reason == "no matching rule"


def test_similar_tool_name_does_not_match() -> None:
    # "read_file" is allowed, but "read_files" is a different tool.
    assert evaluate(request("read_files"), STANDARD_RULES).decision == DENY


# --- Conflicting rules: most restrictive wins -------------------------------------


@pytest.mark.parametrize(
    ("effects", "expected"),
    [
        ([ALLOW, DENY], DENY),
        ([ALLOW, APPROVAL], APPROVAL),
        ([APPROVAL, DENY], DENY),
        ([ALLOW, APPROVAL, DENY], DENY),
    ],
)
def test_most_restrictive_rule_wins(effects: list[Decision], expected: Decision) -> None:
    rules = [rule(f"r{i}", "send_email", effect) for i, effect in enumerate(effects)]
    assert evaluate(request("send_email"), rules).decision == expected
    # Same answer when the rules are listed in reverse.
    assert evaluate(request("send_email"), list(reversed(rules))).decision == expected


def test_tie_is_broken_by_rule_id_not_order() -> None:
    rules = [rule("b-rule", "read_file", ALLOW), rule("a-rule", "read_file", ALLOW)]
    assert evaluate(request("read_file"), rules).matched_rule == "a-rule"
    assert evaluate(request("read_file"), list(reversed(rules))).matched_rule == "a-rule"


# --- Determinism -------------------------------------------------------------------


def test_same_input_gives_same_output() -> None:
    first = evaluate(request("send_email", to="a@b.c"), STANDARD_RULES)
    second = evaluate(request("send_email", to="a@b.c"), STANDARD_RULES)
    assert first == second


def test_arguments_do_not_change_the_decision_yet() -> None:
    # Milestone 1 matches on tool name only.
    assert evaluate(request("read_file", path="a"), STANDARD_RULES).decision == ALLOW
    assert evaluate(request("read_file", path="/etc/passwd"), STANDARD_RULES).decision == ALLOW


# --- Fail closed -------------------------------------------------------------------


class ExplodingRules:
    """Stands in for a broken rule source: raises as soon as it is read."""

    def __init__(self, message: str = "boom") -> None:
        self.message = message

    def __iter__(self) -> Iterator[Rule]:
        raise RuntimeError(self.message)


def test_unexpected_error_means_deny() -> None:
    result = evaluate(request("read_file"), ExplodingRules())  # type: ignore[arg-type]
    assert result.decision == DENY
    assert result.reason == "evaluation error"
    assert result.matched_rule is None


def test_error_never_allows_even_for_an_allowed_tool() -> None:
    # read_file is normally allowed; a failure must still produce DENY.
    result = evaluate(request("read_file"), ExplodingRules())  # type: ignore[arg-type]
    assert result.decision != ALLOW


def test_error_log_does_not_leak_secrets(caplog: pytest.LogCaptureFixture) -> None:
    canary = "sk-live-FAKE-123"  # fake value that must never appear in logs
    with caplog.at_level(logging.DEBUG):
        evaluate(request("read_file", api_key=canary), ExplodingRules(message=canary))  # type: ignore[arg-type]
    assert "policy evaluation failed" in caplog.text
    assert canary not in caplog.text
