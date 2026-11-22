"""Conditions on nested arguments (["headers", "to"]): same strictness as top-level
arguments. A dot in a plain name is just part of the name, as it always was."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from warden.check import check_policy
from warden.engine import evaluate
from warden.models import ActionRequest, Condition, Decision, Op, Rule
from warden.policy import Policy, parse_policy


def rules(*items: dict[str, Any]) -> tuple[Rule, ...]:
    return parse_policy(json.dumps({"rules": list(items)})).rules


def decide(policy: tuple[Rule, ...], arguments: dict[str, Any]) -> tuple[Decision, str]:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "send", "arguments": arguments}
    )
    result = evaluate(request, policy)
    return result.decision, result.reason


ALLOW_COLLEAGUES: dict[str, Any] = {
    "id": "colleagues",
    "tool": "send",
    "effect": "allow",
    "when": [
        {
            "arg": ["headers", "to"],
            "op": "endswith",
            "value": "@mycompany.com",
            "ignore_case": True,
        }
    ],
}
BLOCK_EVIL: dict[str, Any] = {
    "id": "no-evil",
    "tool": "send",
    "effect": "deny",
    "when": [
        {"arg": ["headers", "to"], "op": "endswith", "value": "@evil.net", "ignore_case": True}
    ],
}
POLICY = rules(ALLOW_COLLEAGUES, BLOCK_EVIL)


def test_list_form_reaches_the_nested_value() -> None:
    assert decide(POLICY, {"headers": {"to": "bob@mycompany.com"}})[0] is Decision.ALLOW
    assert decide(POLICY, {"headers": {"to": "x@EVIL.net"}})[0] is Decision.DENY
    assert decide(POLICY, {"headers": {"to": "x@other.org"}}) == (
        Decision.DENY,
        "no matching rule",
    )
    a = Condition.model_validate_json('{"arg": "headers.to", "op": "exists"}')
    b = Condition.model_validate_json('{"arg": ["headers", "to"], "op": "exists"}')
    assert a.path == ("headers.to",) and b.path == ("headers", "to")
    assert b.label == "headers.to"


def test_deep_paths() -> None:
    policy = rules(
        {
            "id": "deep",
            "tool": "send",
            "effect": "allow",
            "when": [{"arg": ["a", "b", "c", "d"], "op": "eq", "value": 1}],
        }
    )
    assert decide(policy, {"a": {"b": {"c": {"d": 1}}}})[0] is Decision.ALLOW
    assert decide(policy, {"a": {"b": {"c": {"d": 2}}}})[0] is Decision.DENY


def test_missing_nested_value_fails_closed() -> None:
    # Missing: the deny rule still applies, the allow rule doesn't.
    cases: list[dict[str, Any]] = [{}, {"headers": {}}, {"headers": {"cc": "x@mycompany.com"}}]
    for arguments in cases:
        decision, reason = decide(POLICY, arguments)
        assert (decision, reason) == (Decision.DENY, "matched rule 'no-evil'")


@pytest.mark.parametrize(
    "headers", ["to: x@evil.net", ["x@evil.net"], 5, True, None, [{"to": "x@evil.net"}]]
)
def test_something_other_than_an_object_on_the_path_denies(headers: Any) -> None:
    assert decide(POLICY, {"headers": headers}) == (
        Decision.DENY,
        "argument 'headers.to' could not be checked",
    )


@pytest.mark.parametrize(
    "to",
    [
        "x@evil.net ",  # trailing space
        "Evil <x@evil.net>",  # display name
        "a@mycompany.com, x@evil.net",  # list
        "x@evil​.net",  # invisible character
        "x@ｅvil.net",  # full-width letter
        123,  # wrong type
    ],
)
def test_same_trick_checks_as_top_level(to: Any) -> None:
    assert decide(POLICY, {"headers": {"to": to}})[0] is Decision.DENY


def test_reason_never_echoes_request_data() -> None:
    _, reason = decide(POLICY, {"headers": "s3cr3t-value"})
    assert "s3cr3t" not in reason


def test_exists_and_missing_on_nested_values() -> None:
    policy = rules(
        {"id": "ok", "tool": "send", "effect": "allow"},
        {
            "id": "no-bcc",
            "tool": "send",
            "effect": "deny",
            "when": [{"arg": ["headers", "bcc"], "op": "exists"}],
        },
        {
            "id": "needs-subject",
            "tool": "send",
            "effect": "require_approval",
            "when": [{"arg": ["headers", "subject"], "op": "missing"}],
        },
    )
    assert decide(policy, {"headers": {"subject": "hi"}})[0] is Decision.ALLOW
    assert decide(policy, {"headers": {"subject": "hi", "bcc": "x"}})[0] is Decision.DENY
    assert decide(policy, {"headers": {}})[0] is Decision.REQUIRE_APPROVAL
    # exists on a path through a non-object can't be answered: deny everything.
    assert decide(policy, {"headers": "bcc"})[0] is Decision.DENY


def test_one_item_list_is_the_same_as_a_plain_name() -> None:
    policy = rules(
        {
            "id": "literal",
            "tool": "send",
            "effect": "allow",
            "when": [{"arg": ["file.name"], "op": "eq", "value": "a.txt"}],
        }
    )
    assert decide(policy, {"file.name": "a.txt"})[0] is Decision.ALLOW
    assert decide(policy, {"file": {"name": "a.txt"}})[0] is Decision.DENY


def test_dotted_names_are_literal_argument_names() -> None:
    """A dot in a plain name is part of the name, so old policies keep their meaning:
    "file.path" is the argument called "file.path", never file -> path."""
    policy = rules(
        {
            "id": "allow-ws",
            "tool": "send",
            "effect": "allow",
            "when": [{"arg": "file.path", "op": "startswith", "value": "/workspace/"}],
        },
        {
            "id": "deny-etc",
            "tool": "send",
            "effect": "deny",
            "when": [{"arg": "file.path", "op": "startswith", "value": "/etc/"}],
        },
    )
    assert decide(policy, {"file.path": "/workspace/a"})[0] is Decision.ALLOW
    assert decide(policy, {"file.path": "/etc/passwd"})[0] is Decision.DENY
    # The nested shape is a different argument: "file.path" is missing, so the deny
    # rule applies and the allow rule doesn't.
    assert decide(policy, {"file": {"path": "/workspace/a"}}) == (
        Decision.DENY,
        "matched rule 'deny-etc'",
    )


@pytest.mark.parametrize(
    "arg",
    [
        "",
        [],
        [""],
        ["a", ""],
        ["a", 1],
        ["bad name"],
        "bad name",
        ["x"] * 9,
    ],
)
def test_bad_paths_fail_to_load(arg: Any) -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate_json(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "r",
                            "tool": "t",
                            "effect": "allow",
                            "when": [{"arg": arg, "op": "exists"}],
                        }
                    ]
                }
            )
        )


def test_python_and_json_loading_agree() -> None:
    from_python = Condition.model_validate({"arg": ["headers", "to"], "op": Op.EXISTS})
    from_json = Condition.model_validate_json('{"arg": ["headers", "to"], "op": "exists"}')
    assert from_python == from_json and from_python.arg == ("headers", "to")


# --- warden check ---------------------------------------------------------------------


def check(tmp_path: Path, policy: dict[str, Any]) -> list[str]:
    path = tmp_path / "p.json"
    path.write_text(json.dumps(policy))
    report = check_policy(path)
    assert not report.errors
    return report.warnings


def test_check_warns_about_unchecked_siblings(tmp_path: Path) -> None:
    warnings = check(tmp_path, {"rules": [ALLOW_COLLEAGUES, BLOCK_EVIL]})
    assert any(w.startswith('W013: rule "no-evil" checks "headers.to"') for w in warnings)
    assert not any('W013: rule "colleagues"' in w for w in warnings)  # allow rules are fine


def test_check_uses_the_first_part_for_argument_lists(tmp_path: Path) -> None:
    spec = {"send": {"arguments": ["headers"]}}
    assert not any(
        w.startswith("W007") for w in check(tmp_path, {"tools": spec, "rules": [ALLOW_COLLEAGUES]})
    )
    typo = {**ALLOW_COLLEAGUES, "when": [{"arg": ["header", "to"], "op": "exists"}]}
    assert any(
        w.startswith("W007") and '"header"' in w
        for w in check(tmp_path, {"tools": spec, "rules": [typo]})
    )


def test_check_tells_a_dotted_name_from_a_nested_path(tmp_path: Path) -> None:
    other = {
        **ALLOW_COLLEAGUES,
        "id": "colleagues-2",
        "when": [{**ALLOW_COLLEAGUES["when"][0], "arg": "headers.to"}],
    }
    warnings = check(tmp_path, {"rules": [ALLOW_COLLEAGUES, other]})
    assert not any(w.startswith("W004") for w in warnings)
    same = {**ALLOW_COLLEAGUES, "id": "colleagues-3"}
    warnings = check(tmp_path, {"rules": [ALLOW_COLLEAGUES, same]})
    assert any(w.startswith("W004") for w in warnings)
