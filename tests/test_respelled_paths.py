"""A path spelled another way ("./.env") can't dodge a rule for a bare name (".env").

Rule values without "/" aren't checked as paths, so before this "./.env" simply didn't
equal ".env" and a deny rule was dodged. Now any compared text that is a path with ".",
".." or empty segments is uncheckable: the whole request is denied."""

import json

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule

RULES = [
    Rule.model_validate_json(json.dumps({"id": "read", "tool": "read_file", "effect": "allow"})),
    Rule.model_validate_json(
        json.dumps(
            {
                "id": "no-secrets",
                "tool": "read_file",
                "effect": "deny",
                "when": [{"arg": "path", "op": "in", "value": [".env", ".npmrc"]}],
            }
        )
    ),
    Rule.model_validate_json(
        json.dumps(
            {
                "id": "no-key",
                "tool": "read_file",
                "effect": "deny",
                "when": [{"arg": "path", "op": "endswith", "value": "id_rsa"}],
            }
        )
    ),
]


def decide(path: str) -> tuple[Decision, str]:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "read_file", "arguments": {"path": path}}
    )
    result = evaluate(request, RULES)
    return result.decision, result.reason


@pytest.mark.parametrize(
    "path",
    [
        "./.env",
        "././.env",
        "src/../.env",
        ".//.env",
        "a//b",
        ".\\.env",
        "dir\\..\\.env",
        "./.npmrc",
        "/home/me/.ssh/id_rsa/.",
        "/home/me/.ssh/id_rsa/./",
        "x/.../.env",
        "x/. /.env",
        "x/..;/.env",
    ],
)
def test_respelled_paths_are_denied(path: str) -> None:
    decision, reason = decide(path)
    assert decision is Decision.DENY
    assert reason.startswith("argument 'path' could not be checked (not a clean path")
    assert path not in reason  # never echoes the argument


@pytest.mark.parametrize("path", [".env", ".npmrc", "/home/me/.ssh/id_rsa"])
def test_the_plain_names_are_still_denied_by_the_rule(path: str) -> None:
    decision, reason = decide(path)
    assert decision is Decision.DENY and "could not be checked" not in reason


@pytest.mark.parametrize(
    "path",
    ["notes.txt", "src/app.py", "/abs/path/file", "dir/", "/", ".hidden/file", "a.b/c..d"],
)
def test_plain_paths_are_unaffected(path: str) -> None:
    assert decide(path)[0] is Decision.ALLOW


def test_urls_are_left_to_the_url_checks() -> None:
    rules = [
        Rule.model_validate_json(json.dumps({"id": "fetch", "tool": "fetch", "effect": "allow"})),
        Rule.model_validate_json(
            json.dumps(
                {
                    "id": "no-x",
                    "tool": "fetch",
                    "effect": "deny",
                    "when": [{"arg": "url", "op": "eq", "value": "x"}],
                }
            )
        ),
    ]
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "fetch", "arguments": {"url": "https://a.com/b//c"}}
    )
    assert evaluate(request, rules).decision is Decision.ALLOW
