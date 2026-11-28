"""Other spellings of an IP address or a local name can't get past a host ALLOW list.

A deny list of IPs can be dodged ("http://2852039166/" is 169.254.169.254, documented in
SECURITY.md); the advice is an allow list. These requests must all be denied by one."""

import json

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision, Rule

ALLOW_API = Rule.model_validate_json(
    json.dumps(
        {
            "id": "api",
            "tool": "fetch",
            "effect": "allow",
            "when": [{"arg": "url", "op": "host_in", "value": ["api.example.com"]}],
        }
    )
)


@pytest.mark.parametrize(
    "url",
    [
        "http://2852039166/latest/meta-data/",
        "http://0xa9.0xfe.0xa9.0xfe/",
        "http://0251.0376.0251.0376/",
        "http://169.254.43518/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[fd00:ec2::254]/",
        "http://127.1/",
        "http://0/",
        "http://localhost/",
        "http://foo.localhost/",
        "http://169.254.169.254.nip.io/",
        "http://api.example.com.evil.net/",
        "http://api.example.com@169.254.169.254/",
        "http://evil.net#@api.example.com/",
        "http://evil.net\\@api.example.com/",
    ],
)
def test_host_allow_list_refuses_other_spellings(url: str) -> None:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "fetch", "arguments": {"url": url}}
    )
    assert evaluate(request, [ALLOW_API]).decision is Decision.DENY


def test_the_allowed_host_itself_passes() -> None:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "fetch", "arguments": {"url": "https://api.example.com/v1"}}
    )
    assert evaluate(request, [ALLOW_API]).decision is Decision.ALLOW
