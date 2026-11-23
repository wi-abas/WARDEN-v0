"""Rules with `otherwise`: one rule, two outcomes, and the fallback is always stricter.

Security properties tested here:
- `otherwise` can never loosen: it must be stricter than `effect` (load error otherwise),
  and a rule with `otherwise` needs at least one condition.
- All conditions hold -> effect; one clearly false -> otherwise; a missing argument ->
  otherwise (the stricter branch); an uncheckable argument -> the WHOLE request denied.
- The rule's outcome still joins every other rule: most restrictive wins.
- The reason says which branch decided, and never echoes the request.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from warden.check import check_policy
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule
from warden.policy import Policy

FETCH_OURS: dict[str, Any] = {
    "id": "fetch-our-hosts",
    "tool": "fetch",
    "effect": "allow",
    "when": [{"arg": "url", "op": "host_in", "value": [".example.com"]}],
    "otherwise": "require_approval",
}


def rules(*items: dict[str, Any]) -> tuple[Rule, ...]:
    return Policy.model_validate_json(json.dumps({"rules": list(items)})).rules


def ask(policy_rules: tuple[Rule, ...], arguments: dict[str, Any], tool: str = "fetch") -> Any:
    request = ActionRequest.model_validate({"agent_id": "a", "tool": tool, "arguments": arguments})
    return evaluate(request, policy_rules)


# --- Loading ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("effect", "otherwise"),
    [
        ("allow", "allow"),
        ("require_approval", "require_approval"),
        ("require_approval", "allow"),
        ("deny", "deny"),
        ("deny", "allow"),
        ("deny", "require_approval"),
    ],
)
def test_otherwise_must_be_stricter_than_effect(effect: str, otherwise: str) -> None:
    with pytest.raises(ValidationError, match="stricter"):
        rules({**FETCH_OURS, "effect": effect, "otherwise": otherwise})


@pytest.mark.parametrize(
    ("effect", "otherwise"),
    [("allow", "require_approval"), ("allow", "deny"), ("require_approval", "deny")],
)
def test_stricter_otherwise_loads(effect: str, otherwise: str) -> None:
    (rule,) = rules({**FETCH_OURS, "effect": effect, "otherwise": otherwise})
    assert rule.otherwise == Decision(otherwise)


@pytest.mark.parametrize("when", [[], None])
def test_otherwise_needs_conditions(when: object) -> None:
    rule = {**FETCH_OURS, "when": when}
    if when is None:
        del rule["when"]
    with pytest.raises(ValidationError, match="at least one 'when'"):
        rules(rule)


@pytest.mark.parametrize("value", [None, "maybe", "ALLOW", 1])
def test_otherwise_value_is_checked(value: object) -> None:
    with pytest.raises(ValidationError):
        rules({**FETCH_OURS, "otherwise": value})


# --- Evaluation ------------------------------------------------------------------------


def test_all_conditions_hold_gives_effect() -> None:
    result = ask(rules(FETCH_OURS), {"url": "https://api.example.com/x"})
    assert result.decision is Decision.ALLOW
    assert result.matched_rule == "fetch-our-hosts"
    assert result.reason == "matched rule 'fetch-our-hosts'"


def test_clearly_false_condition_gives_otherwise() -> None:
    result = ask(rules(FETCH_OURS), {"url": "https://evil.net/secret-token"})
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.matched_rule == "fetch-our-hosts"
    assert result.reason == "rule 'fetch-our-hosts': conditions not met"
    assert "evil" not in result.reason


def test_message_is_used_only_for_the_effect_branch() -> None:
    rule = {**FETCH_OURS, "message": "Our own hosts"}
    assert ask(rules(rule), {"url": "https://example.com/"}).reason == "Our own hosts"
    other = ask(rules(rule), {"url": "https://evil.net/"}).reason
    assert other == "rule 'fetch-our-hosts': conditions not met"


def test_missing_argument_gives_the_stricter_branch() -> None:
    result = ask(rules(FETCH_OURS), {})
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.matched_rule == "fetch-our-hosts"


def test_missing_argument_on_a_require_approval_rule_gives_deny() -> None:
    rule = {**FETCH_OURS, "effect": "require_approval", "otherwise": "deny"}
    assert ask(rules(rule), {}).decision is Decision.DENY


def test_nested_missing_argument_gives_the_stricter_branch() -> None:
    rule = {
        **FETCH_OURS,
        "when": [{"arg": ["headers", "host"], "op": "eq", "value": "a.example.com"}],
    }
    assert ask(rules(rule), {"headers": {}}).decision is Decision.REQUIRE_APPROVAL
    assert ask(rules(rule), {}).decision is Decision.REQUIRE_APPROVAL
    allowed = ask(rules(rule), {"headers": {"host": "a.example.com"}})
    assert allowed.decision is Decision.ALLOW


@pytest.mark.parametrize(
    "url",
    [
        42,
        ["https://api.example.com/"],
        "https://api.example.com@evil.net/",
        "https://api.example.com\\@evil.net",
        "https://api。example.com/",
        "https://api.exam​ple.com/",
    ],
)
def test_uncheckable_argument_denies_the_whole_request(url: object) -> None:
    result = ask(rules(FETCH_OURS), {"url": url})
    assert result.decision is Decision.DENY
    assert result.matched_rule is None
    assert result.reason.startswith("argument 'url' could not be checked")


def test_uncheckable_is_caught_even_when_another_condition_is_false() -> None:
    rule = {
        **FETCH_OURS,
        "when": [
            {"arg": "method", "op": "eq", "value": "GET"},
            {"arg": "url", "op": "host_in", "value": [".example.com"]},
        ],
    }
    result = ask(rules(rule), {"method": "POST", "url": 42})
    assert result.decision is Decision.DENY


def test_every_condition_must_hold_for_the_effect() -> None:
    rule = {
        **FETCH_OURS,
        "when": [
            {"arg": "method", "op": "eq", "value": "GET"},
            {"arg": "url", "op": "host_in", "value": [".example.com"]},
        ],
    }
    url = "https://example.com/"
    assert ask(rules(rule), {"method": "GET", "url": url}).decision is Decision.ALLOW
    assert ask(rules(rule), {"method": "PUT", "url": url}).decision is Decision.REQUIRE_APPROVAL
    assert ask(rules(rule), {"url": url}).decision is Decision.REQUIRE_APPROVAL


def test_exists_condition_with_otherwise() -> None:
    rule = {**FETCH_OURS, "when": [{"arg": "dry_run", "op": "exists"}], "otherwise": "deny"}
    assert ask(rules(rule), {"dry_run": True}).decision is Decision.ALLOW
    assert ask(rules(rule), {}).decision is Decision.DENY


def test_otherwise_joins_other_rules_most_restrictive_wins() -> None:
    deny_secret = {
        "id": "no-secret",
        "tool": "fetch",
        "effect": "deny",
        "when": [{"arg": "url", "op": "host_in", "value": ["secret.example.com"]}],
    }
    allow_evil = {"id": "allow-all", "tool": "fetch", "effect": "allow"}
    policy = rules(FETCH_OURS, deny_secret, allow_evil)
    assert ask(policy, {"url": "https://secret.example.com/"}).decision is Decision.DENY
    # The otherwise branch (require_approval) beats a looser unconditional allow.
    assert ask(policy, {"url": "https://evil.net/"}).decision is Decision.REQUIRE_APPROVAL
    assert ask(policy, {"url": "https://a.example.com/"}).decision is Decision.ALLOW


def test_otherwise_rule_for_another_tool_or_agent_does_not_apply() -> None:
    assert ask(rules(FETCH_OURS), {"url": "x"}, tool="other").decision is Decision.DENY
    rule = {**FETCH_OURS, "agents": ["someone-else"]}
    result = ask(rules(rule), {"url": "https://evil.net/"})
    assert result.decision is Decision.DENY
    assert result.reason == "no matching rule"


def test_tie_between_branches_uses_smallest_rule_id() -> None:
    a = {**FETCH_OURS, "id": "b-rule"}
    b = {"id": "a-rule", "tool": "fetch", "effect": "require_approval"}
    result = ask(rules(a, b), {"url": "https://evil.net/"})
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.matched_rule == "a-rule"


# --- warden check ----------------------------------------------------------------------


def codes(tmp_path: Path, *items: dict[str, Any]) -> list[str]:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": list(items)}))
    report = check_policy(path)
    assert report.errors == []
    return [w.split(":")[0] for w in report.warnings]


@pytest.mark.parametrize("op", ["neq", "missing"])
def test_w016_double_negative(tmp_path: Path, op: str) -> None:
    cond: dict[str, Any] = {"arg": "mode", "op": op}
    if op == "neq":
        cond["value"] = "x"
    found = codes(tmp_path, {**FETCH_OURS, "when": [cond]})
    assert "W016" in found


def test_no_w016_for_positive_conditions(tmp_path: Path) -> None:
    assert "W016" not in codes(tmp_path, FETCH_OURS)
    plain_neq = {
        "id": "r",
        "tool": "fetch",
        "effect": "deny",
        "when": [{"arg": "m", "op": "neq", "value": "x"}],
    }
    assert "W016" not in codes(tmp_path, plain_neq)


def test_w003_otherwise_rule_always_applies(tmp_path: Path) -> None:
    # "fetch-our-hosts" always gives at least allow; that doesn't kill anything.
    allow = {"id": "allow-all", "tool": "fetch", "effect": "allow"}
    assert "W003" not in codes(tmp_path, FETCH_OURS, allow)
    # A require_approval/deny rule with otherwise always gives at least require_approval,
    # so an unconditional allow for the same tool can never win.
    strict = {**FETCH_OURS, "effect": "require_approval", "otherwise": "deny"}
    assert "W003" in codes(tmp_path, strict, allow)


def test_w003_considers_the_otherwise_branch_of_the_dead_rule(tmp_path: Path) -> None:
    always_approval = {"id": "approve-all", "tool": "fetch", "effect": "require_approval"}
    # FETCH_OURS can still give require_approval (a tie, not dead).
    assert "W003" not in codes(tmp_path, FETCH_OURS, always_approval)
    always_deny = {"id": "deny-all", "tool": "fetch", "effect": "deny"}
    assert "W003" in codes(tmp_path, FETCH_OURS, always_deny)
    # ... but an otherwise "deny" branch can't be beaten by an always-require_approval rule.
    deny_branch = {**FETCH_OURS, "otherwise": "deny"}
    assert "W003" not in codes(tmp_path, deny_branch, always_approval)


def test_w004_otherwise_makes_rules_different(tmp_path: Path) -> None:
    same = {**FETCH_OURS, "id": "copy"}
    assert "W004" in codes(tmp_path, FETCH_OURS, same)
    different = {**FETCH_OURS, "id": "copy", "otherwise": "deny"}
    assert "W004" not in codes(tmp_path, FETCH_OURS, different)
