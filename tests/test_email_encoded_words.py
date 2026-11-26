"""Email rules refuse MIME encoded-words and local parts starting with "-" or "|".

Some mail software decodes "=?utf-8?q?...?=" into another address than the text Warden
compared, and sendmail-style tools read "-x@..." as an option and "|cmd@..." as a pipe.
Such a value can't be checked, so the whole request is denied."""

import json
from typing import Any

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import Policy

COMPANY_ONLY = [
    {
        "id": "company",
        "tool": "send_email",
        "effect": "allow",
        "when": [{"arg": "to", "op": "endswith", "value": "@mycompany.com", "ignore_case": True}],
    }
]
DENY_EVIL = [
    {"id": "all", "tool": "send_email", "effect": "allow"},
    {
        "id": "no-evil",
        "tool": "send_email",
        "effect": "deny",
        "when": [{"arg": "to", "op": "eq", "value": "boss@evil.com", "ignore_case": True}],
    },
]


def ask(rules: Any, to: str) -> tuple[Decision, str]:
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "send_email", "arguments": {"to": to}}
    )
    result = evaluate(request, policy.rules)
    return result.decision, result.reason


@pytest.mark.parametrize(
    "to",
    [
        "=?utf-8?q?evil=40x.com?=@mycompany.com",
        "=?UTF-8?B?ZXZpbEB4LmNvbQ==?=@mycompany.com",
        "bob=?utf-8?q?=00?=@mycompany.com",
        "bob@=?utf-8?q?mycompany?=.mycompany.com",
        "-oQ/tmp/x@mycompany.com",
        "|touch_pwned@mycompany.com",
    ],
)
def test_tricky_addresses_cant_pass_an_allow_list(to: str) -> None:
    decision, reason = ask(COMPANY_ONLY, to)
    assert decision is Decision.DENY
    assert "could not be checked" in reason and to not in reason


@pytest.mark.parametrize(
    "to", ["=?utf-8?q?boss?=@evil.com", "boss@=?utf-8?q?evil?=.com", "-boss@evil.com"]
)
def test_tricky_addresses_cant_dodge_a_deny_rule(to: str) -> None:
    assert ask(DENY_EVIL, to)[0] is Decision.DENY


@pytest.mark.parametrize(
    "to",
    [
        "bob@mycompany.com",
        "bob-smith@mycompany.com",
        "bob=smith@mycompany.com",
        "a?b@mycompany.com",
        "bob+tag@mycompany.com",
    ],
)
def test_ordinary_addresses_still_allowed(to: str) -> None:
    assert ask(COMPANY_ONLY, to)[0] is Decision.ALLOW
