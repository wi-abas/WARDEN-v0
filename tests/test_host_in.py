"""host_in compares a URL's real host, so URL disguises can't dodge it."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from warden.check import check_policy
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule
from warden.policy import Policy

BLOCK = [
    {"id": "all", "tool": "fetch", "effect": "allow"},
    {
        "id": "block",
        "tool": "fetch",
        "effect": "deny",
        "when": [{"arg": "url", "op": "host_in", "value": ["evil.net", ".evil.org"]}],
    },
]
ONLY = [
    {
        "id": "only",
        "tool": "fetch",
        "effect": "allow",
        "when": [{"arg": "url", "op": "host_in", "value": ["api.good.com"]}],
    }
]


def ask(rules: Any, url: object) -> Decision:
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "fetch", "arguments": {"url": url}}
    )
    return evaluate(request, policy.rules).decision


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.net/x",
        "http://evil.net/x",
        "HTTPS://EVIL.NET/x",
        "https://evil.net:443/x",
        "https://evil.net:8443/x",
        "https://evil.net./x",
        "https://evil.net",
        "ftp://evil.net/x",
        "https://good.com@evil.net/x",
        "https://ｅvil.net/x",
        "https://evil。net/x",
        "https://evi­l.net/x",
        "https://a.b.evil.org/x",
        "https://evil.org/x",
        "//evil.net/x",
        "https:/evil.net/x",
        "https://ev%69l.net/x",
        "not a url",
        42,
    ],
)
def test_disguised_hosts_are_blocked(url: object) -> None:
    assert ask(BLOCK, url) == Decision.DENY


@pytest.mark.parametrize(
    "url",
    [
        "https://good.com/x",
        "https://notevil.net/x",
        "https://evil.net.good.com/x",
        "https://evil.org.good.com/",
    ],
)
def test_other_hosts_pass_the_deny_list(url: str) -> None:
    assert ask(BLOCK, url) == Decision.ALLOW


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://api.good.com/v1", Decision.ALLOW),
        ("http://API.GOOD.COM:8080/", Decision.ALLOW),
        ("https://api.good.com.evil.net/", Decision.DENY),
        ("https://x.api.good.com/", Decision.DENY),
        ("https://api.good.com@evil.net/", Decision.DENY),
    ],
)
def test_allow_list(url: str, expected: Decision) -> None:
    assert ask(ONLY, url) == expected


def test_international_hosts_must_be_punycode() -> None:
    rules = [
        {
            "id": "r",
            "tool": "fetch",
            "effect": "allow",
            "when": [{"arg": "url", "op": "host_in", "value": ["xn--mnchen-3ya.de"]}],
        }
    ]
    assert ask(rules, "https://xn--mnchen-3ya.de/") == Decision.ALLOW
    assert ask(rules, "https://münchen.de/") == Decision.DENY  # Unicode form: refused


def test_idna_mismatch_cannot_dodge_a_deny_rule() -> None:
    # Python's IDNA2003 turns straße.de into strasse.de; browsers (IDNA2008) go to
    # xn--strae-oqa.de. Refusing the Unicode form closes that gap.
    rules = [
        {"id": "all", "tool": "fetch", "effect": "allow"},
        {
            "id": "b",
            "tool": "fetch",
            "effect": "deny",
            "when": [{"arg": "url", "op": "host_in", "value": ["xn--strae-oqa.de"]}],
        },
    ]
    assert ask(rules, "https://straße.de/") == Decision.DENY


@pytest.mark.parametrize(
    "value",
    [
        [],
        "evil.net",
        ["EVIL.NET"],
        ["evil.net/"],
        ["https://evil.net"],
        ["*.evil.net"],
        ["evil..net"],
        [5],
    ],
)
def test_bad_host_lists_are_rejected(value: object) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate_json(
            json.dumps(
                {
                    "id": "r",
                    "tool": "t",
                    "effect": "deny",
                    "when": [{"arg": "url", "op": "host_in", "value": value}],
                }
            )
        )


def test_host_in_rejects_ignore_case() -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate_json(
            json.dumps(
                {
                    "id": "r",
                    "tool": "t",
                    "effect": "deny",
                    "when": [
                        {"arg": "url", "op": "host_in", "value": ["x.com"], "ignore_case": True}
                    ],
                }
            )
        )


def test_w012_suggests_host_in(tmp_path: Path) -> None:
    rules = [
        {"id": "all", "tool": "fetch", "effect": "allow"},
        {
            "id": "block",
            "tool": "fetch",
            "effect": "deny",
            "when": [
                {
                    "arg": "url",
                    "op": "startswith",
                    "value": "https://evil.net/",
                    "ignore_case": True,
                }
            ],
        },
    ]
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"tools": {"fetch": {"arguments": ["url"]}}, "rules": rules}))
    assert [w[:4] for w in check_policy(path).warnings] == ["W012"]
    path.write_text(json.dumps({"tools": {"fetch": {"arguments": ["url"]}}, "rules": BLOCK}))
    assert check_policy(path).warnings == []
