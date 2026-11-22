"""Path and email tricks can't slip past rules; harmless names aren't blocked."""

import json
from pathlib import Path
from typing import Any

import pytest

from warden.check import check_policy
from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import Policy


def ask(rules: Any, tool: str, **arguments: object) -> Decision:
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate({"agent_id": "a", "tool": tool, "arguments": arguments})
    return evaluate(request, policy.rules).decision


DENY_ETC = [
    {"id": "all", "tool": "read_file", "effect": "allow"},
    {
        "id": "no-etc",
        "tool": "read_file",
        "effect": "deny",
        "when": [{"arg": "path", "op": "startswith", "value": "/etc/", "ignore_case": True}],
    },
]


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "//etc/passwd",
        "/./etc/passwd",
        "/ETC/passwd",
        "/etc/../etc/passwd",
        "/var/../etc/passwd",
        "/etc\\passwd",
        "/data/.",
        "/data/..",
    ],
)
def test_path_tricks_cannot_dodge_a_deny_rule(path: str) -> None:
    assert ask(DENY_ETC, "read_file", path=path) == Decision.DENY


@pytest.mark.parametrize("path", ["/data/report.txt", "/data/notes..txt", "/data/", "/home/a"])
def test_clean_paths_still_allowed(path: str) -> None:
    assert ask(DENY_ETC, "read_file", path=path) == Decision.ALLOW


def test_eq_path_rule_also_protected() -> None:
    rules = [
        {"id": "all", "tool": "read_file", "effect": "allow"},
        {
            "id": "no-shadow",
            "tool": "read_file",
            "effect": "deny",
            "when": [{"arg": "path", "op": "eq", "value": "/etc/shadow"}],
        },
    ]
    assert ask(rules, "read_file", path="//etc/shadow") == Decision.DENY


DENY_EVIL = [
    {"id": "all", "tool": "send_email", "effect": "allow"},
    {
        "id": "no-evil",
        "tool": "send_email",
        "effect": "deny",
        "when": [{"arg": "to", "op": "endswith", "value": "@evil.com", "ignore_case": True}],
    },
]


@pytest.mark.parametrize(
    "to",
    [
        "x@evil.com",
        "x@EVIL.com",
        "x@evil.com ",
        " x@evil.com",
        "x@evil.com.",
        "Evil <x@evil.com>",
        "a@ok.com, x@evil.com",
        "a@ok.com;x@evil.com",
        "x@evil.com\n",
    ],
)
def test_email_tricks_cannot_dodge_a_deny_rule(to: str) -> None:
    assert ask(DENY_EVIL, "send_email", to=to) == Decision.DENY


COMPANY_ONLY = [
    {
        "id": "company",
        "tool": "send_email",
        "effect": "allow",
        "when": [{"arg": "to", "op": "endswith", "value": "@mycompany.com", "ignore_case": True}],
    }
]


def test_recipient_list_cannot_sneak_past_an_allow_list() -> None:
    assert ask(COMPANY_ONLY, "send_email", to="evil@x.com, bob@mycompany.com") == Decision.DENY
    assert ask(COMPANY_ONLY, "send_email", to="bob@mycompany.com") == Decision.ALLOW


def test_non_path_non_email_text_is_untouched() -> None:
    rules = [
        {
            "id": "r",
            "tool": "t",
            "effect": "allow",
            "when": [{"arg": "name", "op": "startswith", "value": "report"}],
        }
    ]
    assert ask(rules, "t", name="report  final..v2") == Decision.ALLOW


def write(tmp_path: Path, rules: Any) -> Path:
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"rules": rules}))
    return path


def test_w009_case_sensitive_path_deny_rule(tmp_path: Path) -> None:
    case_sensitive = json.loads(json.dumps(DENY_ETC))
    case_sensitive[1]["when"][0]["ignore_case"] = False
    codes = [w[:4] for w in check_policy(write(tmp_path, case_sensitive)).warnings]
    assert codes == ["W001", "W009"]  # W001: deny-list without an argument list
    codes = [w[:4] for w in check_policy(write(tmp_path, DENY_ETC)).warnings]
    assert codes == ["W001"]


def test_w009_not_raised_when_nothing_looser_exists(tmp_path: Path) -> None:
    rules = [
        {
            "id": "w",
            "tool": "write_file",
            "effect": "require_approval",
            "when": [{"arg": "path", "op": "startswith", "value": "/workspace/"}],
        }
    ]
    assert check_policy(write(tmp_path, rules)).warnings == []
