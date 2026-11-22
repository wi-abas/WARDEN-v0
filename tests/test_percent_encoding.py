"""%-encoding can't be used to escape path or URL rules."""

import json
from typing import Any

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import Policy


def ask(when: dict[str, Any], tool: str, arg: str, value: str, extra: Any = ()) -> Decision:
    rules = [*extra, {"id": "rule", "tool": tool, "effect": "allow", "when": [when]}]
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": tool, "arguments": {arg: value}}
    )
    return evaluate(request, policy.rules).decision


DATA = {"arg": "path", "op": "startswith", "value": "/data/"}


@pytest.mark.parametrize(
    "path",
    [
        "/data/%2e%2e/etc/passwd",
        "/data/%2E%2E%2Fetc/passwd",
        "/data/..%2fetc/passwd",
        "/data/%252e%252e/etc/passwd",
        "/data/%65tc",
        "/data/a%5cb",
    ],
)
def test_encoded_paths_cannot_escape_an_allow_list(path: str) -> None:
    assert ask(DATA, "read_file", "path", path) == Decision.DENY


def test_encoded_paths_cannot_dodge_a_deny_list() -> None:
    deny_etc = [{"id": "all", "tool": "read_file", "effect": "allow"}]
    when = {"arg": "path", "op": "startswith", "value": "/etc/", "ignore_case": True}
    rules = [*deny_etc, {"id": "no-etc", "tool": "read_file", "effect": "deny", "when": [when]}]
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    for path in ["%2fetc/passwd", "/%65tc/passwd", "/%45TC/passwd"]:
        request = ActionRequest.model_validate(
            {"agent_id": "a", "tool": "read_file", "arguments": {"path": path}}
        )
        assert evaluate(request, policy.rules).decision == Decision.DENY


PUBLIC = {"arg": "url", "op": "startswith", "value": "https://api.good.com/public/"}


@pytest.mark.parametrize(
    "url",
    [
        "https://api.good.com/public/%2e%2e/admin",
        "https://api.good.com/public/..%2fadmin",
        "https://api.good.com/public/%252e%252e/admin",
        "https://api.good.com/public/a%5c..%5cb",
        "https://api.good%2ecom/public/x",
    ],
)
def test_encoded_urls_cannot_escape_an_allow_list(url: str) -> None:
    assert ask(PUBLIC, "fetch", "url", url) == Decision.DENY


@pytest.mark.parametrize(
    "url",
    [
        "https://api.good.com/public/my%20file.txt",
        "https://api.good.com/public/q?x=a%20b&y=%3D",
        "https://api.good.com/public/caf%C3%A9",
    ],
)
def test_ordinary_url_escapes_still_work(url: str) -> None:
    assert ask(PUBLIC, "fetch", "url", url) == Decision.ALLOW
