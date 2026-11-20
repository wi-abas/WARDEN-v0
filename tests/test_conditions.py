"""Argument rules ("when" conditions): matching, type safety and policy validation."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule
from warden.policy import load_rules


def rule(id: str, effect: str, *when: dict, tool: str = "send_invoice") -> Rule:
    # Built from JSON, exactly like the real policy file is loaded.
    return Rule.model_validate_json(
        json.dumps({"id": id, "tool": tool, "effect": effect, "when": list(when)})
    )


def cond(arg: str, op: str, value: object) -> dict:
    return {"arg": arg, "op": op, "value": value}


def request(tool: str = "send_invoice", **arguments: object) -> ActionRequest:
    return ActionRequest.model_validate({"agent_id": "a", "tool": tool, "arguments": arguments})


INVOICE_RULES = [
    rule("big-invoice", "require_approval", cond("amount", "gt", 500)),
    rule("small-invoice", "allow", cond("amount", "lte", 500)),
]


# --- The invoice example -------------------------------------------------------------


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (200, Decision.ALLOW),
        (500, Decision.ALLOW),
        (500.01, Decision.REQUIRE_APPROVAL),
        (5000, Decision.REQUIRE_APPROVAL),
        (-1, Decision.ALLOW),
    ],
)
def test_invoice_amounts(amount: float, expected: Decision) -> None:
    assert evaluate(request(amount=amount), INVOICE_RULES).decision == expected


def test_missing_argument_matches_nothing_so_deny() -> None:
    result = evaluate(request(recipient="x@y.z"), INVOICE_RULES)
    assert result.decision == Decision.DENY
    assert result.reason == "no matching rule"


# --- Each op -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("condition", "value", "holds"),
    [
        (cond("x", "eq", "eu"), "eu", True),
        (cond("x", "eq", "eu"), "EU", False),
        (cond("x", "eq", 1), 1.0, True),
        (cond("x", "eq", True), True, True),
        (cond("x", "neq", "eu"), "us", True),
        (cond("x", "neq", "eu"), "eu", False),
        (cond("x", "gt", 5), 6, True),
        (cond("x", "gt", 5), 5, False),
        (cond("x", "gte", 5), 5, True),
        (cond("x", "lt", 5), 4.9, True),
        (cond("x", "lt", 5), 5, False),
        (cond("x", "lte", 5), 5, True),
        (cond("x", "in", ["eu", "us"]), "us", True),
        (cond("x", "in", ["eu", "us"]), "cn", False),
        (cond("x", "startswith", "/data/"), "/data/a.txt", True),
        (cond("x", "startswith", "/data/"), "/etc/passwd", False),
        (cond("x", "startswith", "/data/"), "/data", False),
    ],
)
def test_ops(condition: dict, value: object, holds: bool) -> None:
    rules = [rule("r", "allow", condition)]
    expected = Decision.ALLOW if holds else Decision.DENY
    assert evaluate(request(x=value), rules).decision == expected


def test_all_conditions_must_hold() -> None:
    rules = [rule("r", "allow", cond("amount", "lte", 500), cond("currency", "eq", "eur"))]
    assert evaluate(request(amount=100, currency="eur"), rules).decision == Decision.ALLOW
    assert evaluate(request(amount=100, currency="usd"), rules).decision == Decision.DENY
    assert evaluate(request(amount=900, currency="eur"), rules).decision == Decision.DENY


def test_rule_without_when_still_matches_any_arguments() -> None:
    rules = [Rule.model_validate_json('{"id":"r","tool":"read_file","effect":"allow"}')]
    assert evaluate(request("read_file", path="anything"), rules).decision == Decision.ALLOW


# --- Can't be tricked ----------------------------------------------------------------

# A typical "deny-list" policy: allow invoices, but block big ones.
DENY_BIG = [
    rule("allow-invoices", "allow"),
    rule("block-big", "deny", cond("amount", "gt", 10000)),
]


@pytest.mark.parametrize(
    "sneaky_amount",
    ["50000", True, None, [50000], {"value": 50000}],
)
def test_wrong_type_cannot_dodge_a_deny_rule(sneaky_amount: object) -> None:
    result = evaluate(request(amount=sneaky_amount), DENY_BIG)
    assert result.decision == Decision.DENY
    assert result.reason == "argument 'amount' could not be checked"


def test_deny_rule_still_works_normally() -> None:
    assert evaluate(request(amount=50000), DENY_BIG).decision == Decision.DENY
    assert evaluate(request(amount=50), DENY_BIG).decision == Decision.ALLOW


@pytest.mark.parametrize(
    "path",
    ["/data/../etc/passwd", "/data/..", "/data/a/../../etc", "/data/..\\x"],
)
def test_dot_dot_paths_are_denied(path: str) -> None:
    rules = [rule("r", "allow", cond("path", "startswith", "/data/"), tool="read_file")]
    result = evaluate(request("read_file", path=path), rules)
    assert result.decision == Decision.DENY
    assert result.reason == "argument 'path' could not be checked"


def test_dot_dot_cannot_dodge_a_deny_rule() -> None:
    rules = [
        rule("allow-read", "allow", tool="read_file"),
        rule("block-etc", "deny", cond("path", "startswith", "/etc/"), tool="read_file"),
    ]
    assert evaluate(request("read_file", path="/etc/../etc/passwd"), rules).decision == (
        Decision.DENY
    )


def test_true_is_not_treated_as_the_number_1() -> None:
    rules = [rule("r", "allow", cond("x", "eq", 1))]
    assert evaluate(request(x=True), rules).decision == Decision.DENY


def test_neq_with_wrong_type_is_denied() -> None:
    # "currency neq usd" must not say True just because 5 is not "usd".
    rules = [rule("r", "allow", cond("currency", "neq", "usd"))]
    assert evaluate(request(currency=5), rules).decision == Decision.DENY


def test_uncheckable_caught_whatever_the_condition_order() -> None:
    a = cond("region", "eq", "eu")
    b = cond("amount", "gt", 10)
    for when in [(a, b), (b, a)]:
        rules = [rule("allow-all", "allow"), rule("block", "deny", *when)]
        result = evaluate(request(region="us", amount="999"), rules)
        assert result.reason == "argument 'amount' could not be checked"


def test_huge_number_does_not_crash() -> None:
    assert evaluate(request(amount=10**400), INVOICE_RULES).decision == (Decision.REQUIRE_APPROVAL)


def test_argument_value_never_appears_in_the_reason() -> None:
    canary = "sk-live-FAKE-123"  # fake secret used to detect leaks
    result = evaluate(request(amount=canary), INVOICE_RULES)
    assert canary not in result.model_dump_json()


# --- Bad conditions in the policy file are rejected at load time ---------------------


@pytest.mark.parametrize(
    "bad",
    [
        cond("amount", "gt", "500"),  # number op with text
        cond("amount", "gt", True),  # bool is not a number
        cond("amount", "regex", ".*"),  # unknown op
        cond("path", "startswith", ""),  # empty prefix matches everything
        cond("path", "startswith", 5),
        cond("region", "in", []),  # empty list
        cond("region", "in", "eu"),  # not a list
        cond("region", "in", [["eu"]]),  # nested
        cond("region", "in", ["x"] * 101),  # too many
        cond("region", "eq", None),
        cond("region", "eq", {"a": 1}),
        cond("bad name!", "eq", "x"),  # bad argument name
        {"arg": "x", "op": "eq"},  # missing value
        {"arg": "x", "op": "eq", "value": 1, "extra": 1},  # unknown field
    ],
)
def test_invalid_conditions_are_rejected(bad: dict) -> None:
    with pytest.raises(ValidationError):
        rule("r", "allow", bad)


def test_too_many_conditions_rejected() -> None:
    with pytest.raises(ValidationError):
        rule("r", "allow", *[cond("x", "eq", i) for i in range(21)])


def test_bad_condition_in_file_loads_zero_rules(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    good = {"id": "ok", "tool": "read_file", "effect": "allow"}
    bad = {"id": "bad", "tool": "send_invoice", "effect": "allow", "when": [cond("a", "gt", "x")]}
    path.write_text(json.dumps({"rules": [good, bad]}))
    assert load_rules(path) == ()


def test_conditions_load_from_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "small",
                        "tool": "send_invoice",
                        "effect": "allow",
                        "when": [cond("amount", "lte", 500)],
                    }
                ]
            }
        )
    )
    rules = load_rules(path)
    assert evaluate(request(amount=100), rules).decision == Decision.ALLOW
    assert evaluate(request(amount=900), rules).decision == Decision.DENY
