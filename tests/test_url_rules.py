"""URL rules work, and URL tricks can't slip past them."""

import json
from typing import Any

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import Policy


def ask(rules: Any, url: str) -> Decision:
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "fetch", "arguments": {"url": url}}
    )
    return evaluate(request, policy.rules).decision


ALLOW_API = [
    {
        "id": "api",
        "tool": "fetch",
        "effect": "allow",
        "when": [{"arg": "url", "op": "startswith", "value": "https://api.mycompany.com/"}],
    }
]


@pytest.mark.parametrize(
    "url",
    [
        "https://api.mycompany.com/v1/users",
        "https://api.mycompany.com/",
        "https://api.mycompany.com/u/@bob",  # "@" in the path is fine for URLs
        "https://api.mycompany.com/a?b=c#d",
    ],
)
def test_legit_urls_allowed(url: str) -> None:
    assert ask(ALLOW_API, url) == Decision.ALLOW


@pytest.mark.parametrize(
    "url",
    [
        "https://api.mycompany.com/../admin",
        "https://api.mycompany.com//x",
        "https://api.mycompany.com/a/./b",
        "https://api.mycompany.com\\@evil.net/",
        "https://api.mycompany.com /x",
        "https://evil.net/https://api.mycompany.com/",
    ],
)
def test_url_tricks_denied(url: str) -> None:
    assert ask(ALLOW_API, url) == Decision.DENY


DENY_EVIL = [
    {"id": "all", "tool": "fetch", "effect": "allow"},
    {
        "id": "no-evil",
        "tool": "fetch",
        "effect": "deny",
        "when": [
            {"arg": "url", "op": "startswith", "value": "https://evil.net/", "ignore_case": True}
        ],
    },
]


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.net/x",
        "HTTPS://EVIL.NET/x",
        "https://good.com@evil.net/x",  # userinfo trick: the real host is evil.net
        "https://evil.net/../x",
        "not a url",
    ],
)
def test_url_tricks_cannot_dodge_a_deny_rule(url: str) -> None:
    assert ask(DENY_EVIL, url) == Decision.DENY


def test_other_hosts_still_allowed_by_the_deny_list() -> None:
    assert ask(DENY_EVIL, "https://good.com/x") == Decision.ALLOW


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.net./x",
        "https://evil.net:/x",
        "https://evil.net::/x",
        "https://evil.net:./x",
        "https://evil.net::443/x",
        "https://EVIL.NET./x",
    ],
)
def test_trailing_dot_and_empty_port_cannot_dodge_text_rules(url: str) -> None:
    assert ask(DENY_EVIL, url) == Decision.DENY


@pytest.mark.parametrize(
    "url", ["https://good.com:8443/x", "https://[::1]:8000/x", "https://[::1]/x"]
)
def test_real_ports_and_ipv6_still_work(url: str) -> None:
    assert ask(DENY_EVIL, url) == Decision.ALLOW
