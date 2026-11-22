"""Invisible and look-alike characters can't slip past text rules."""

import json
from typing import Any

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import Policy


def ask(rules: Any, tool: str, **arguments: object) -> Decision:
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate({"agent_id": "a", "tool": tool, "arguments": arguments})
    return evaluate(request, policy.rules).decision


def deny_list(tool: str, arg: str, op: str, value: str) -> list[dict[str, Any]]:
    return [
        {"id": "all", "tool": tool, "effect": "allow"},
        {
            "id": "block",
            "tool": tool,
            "effect": "deny",
            "when": [{"arg": arg, "op": op, "value": value, "ignore_case": True}],
        },
    ]


@pytest.mark.parametrize(
    "to",
    [
        "x@ｅvil.com",
        "X@ＥVIL.COM",
        "x@evil。com",
        "x@evil.com​",
        "x@evi­l.com",
        "x@evil‍.com",
        "x@evil.com‮",
    ],
)
def test_email_unicode_tricks(to: str) -> None:
    assert ask(deny_list("send_email", "to", "endswith", "@evil.com"), "send_email", to=to) == (
        Decision.DENY
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://ｅvil.net/x",
        "https://evil。net/x",
        "https://evil．net/x",
        "https://evi­l.net/x",
        "https://evil.net​/x",
    ],
)
def test_url_unicode_tricks(url: str) -> None:
    rules = deny_list("fetch", "url", "startswith", "https://evil.net/")
    assert ask(rules, "fetch", url=url) == Decision.DENY


@pytest.mark.parametrize("path", ["/ｅtc/passwd", "/et​c/passwd", "/etc­/passwd"])
def test_path_unicode_tricks(path: str) -> None:
    rules = deny_list("read_file", "path", "startswith", "/etc/")
    assert ask(rules, "read_file", path=path) == Decision.DENY


def test_eq_on_plain_text_refuses_lookalikes() -> None:
    rules = deny_list("run", "user", "eq", "root")
    assert ask(rules, "run", user="ｒoot") == Decision.DENY
    assert ask(rules, "run", user="r​oot") == Decision.DENY
    assert ask(rules, "run", user="alice") == Decision.ALLOW


def test_decomposed_accents_match_composed_policy_values() -> None:
    rules = [
        {
            "id": "r",
            "tool": "read_file",
            "effect": "allow",
            "when": [{"arg": "path", "op": "eq", "value": "/data/café.txt"}],
        }
    ]
    decomposed = "/data/café.txt"  # how macOS often stores "é"
    assert ask(rules, "read_file", path=decomposed) == Decision.ALLOW


@pytest.mark.parametrize("text", ["Zürich", "naïve", "日本語", "Straße"])
def test_normal_non_ascii_text_still_works(text: str) -> None:
    rules = [
        {
            "id": "r",
            "tool": "t",
            "effect": "allow",
            "when": [{"arg": "city", "op": "eq", "value": text}],
        }
    ]
    assert ask(rules, "t", city=text) == Decision.ALLOW
