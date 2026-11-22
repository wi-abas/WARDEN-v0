"""endswith and ignore_case: email-domain rules that can't be dodged by case tricks."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from warden.check import check_policy
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule


def rule(id: str, effect: str, *when: dict) -> Rule:
    return Rule.model_validate_json(
        json.dumps({"id": id, "tool": "send_email", "effect": effect, "when": list(when)})
    )


def send(to: object) -> ActionRequest:
    return ActionRequest.model_validate(
        {"agent_id": "a", "tool": "send_email", "arguments": {"to": to}}
    )


def ends(value: str, ignore_case: bool = False) -> dict:
    return {"arg": "to", "op": "endswith", "value": value, "ignore_case": ignore_case}


COMPANY_ONLY = [rule("company-only", "allow", ends("@mycompany.com", ignore_case=True))]


@pytest.mark.parametrize(
    ("to", "expected"),
    [
        ("bob@mycompany.com", Decision.ALLOW),
        ("Bob@MyCompany.COM", Decision.ALLOW),
        ("bob@mycompany.com.evil.com", Decision.DENY),
        ("bob@evilmycompany.com", Decision.DENY),  # the "@" in the value stops this
        ("bob@gmail.com", Decision.DENY),
    ],
)
def test_company_domain_allow_list(to: str, expected: Decision) -> None:
    assert evaluate(send(to), COMPANY_ONLY).decision == expected


def test_case_sensitive_by_default() -> None:
    rules = [rule("r", "allow", ends("@mycompany.com"))]
    assert evaluate(send("bob@MYCOMPANY.com"), rules).decision == Decision.DENY


def test_ignore_case_stops_the_uppercase_trick_on_a_deny_rule() -> None:
    rules = [rule("allow", "allow"), rule("block", "deny", ends("@evil.com", ignore_case=True))]
    assert evaluate(send("x@EVIL.com"), rules).decision == Decision.DENY


def test_endswith_wrong_type_denies_the_request() -> None:
    result = evaluate(send(42), COMPANY_ONLY)
    assert result.reason == "argument 'to' could not be checked"


def test_dot_dot_is_fine_for_endswith() -> None:
    # The ".." rule protects path prefixes; it doesn't apply to endswith.
    rules = [rule("r", "allow", {"arg": "to", "op": "endswith", "value": ".txt"})]
    assert evaluate(send("notes..txt"), rules).decision == Decision.ALLOW


@pytest.mark.parametrize(
    ("op", "value", "to", "holds"),
    [
        ("eq", "Bob@X.com", "bob@x.com", True),
        ("neq", "Bob@X.com", "bob@x.com", False),
        ("in", ["A@X.com", "B@X.com"], "b@x.COM", True),
        ("startswith", "ADMIN", "admin-1", True),
    ],
)
def test_ignore_case_on_other_text_ops(op: str, value: object, to: str, holds: bool) -> None:
    rules = [rule("r", "allow", {"arg": "to", "op": op, "value": value, "ignore_case": True})]
    assert evaluate(send(to), rules).decision == (Decision.ALLOW if holds else Decision.DENY)


@pytest.mark.parametrize(
    "condition",
    [
        {"arg": "to", "op": "endswith", "value": ""},
        {"arg": "to", "op": "endswith", "value": 5},
        {"arg": "to", "op": "gt", "value": 5, "ignore_case": True},
        {"arg": "to", "op": "eq", "value": 5, "ignore_case": True},
        {"arg": "to", "op": "in", "value": ["a", 1], "ignore_case": True},
        {"arg": "to", "op": "exists", "ignore_case": True},
        {"arg": "to", "op": "endswith", "value": "x", "ignore_case": "yes"},
    ],
)
def test_invalid_conditions_rejected(condition: dict) -> None:
    with pytest.raises(ValidationError):
        rule("r", "allow", condition)


def test_w008_case_sensitive_email_check(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    for ignore_case, expected in [(False, ["W008"]), (True, [])]:
        cond = ends("@evil.com", ignore_case)
        rules = [{"id": "r", "tool": "send_email", "effect": "deny", "when": [cond]}]
        path.write_text(json.dumps({"rules": rules}))
        assert [w[:4] for w in check_policy(path).warnings] == expected
