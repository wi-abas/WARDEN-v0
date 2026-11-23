"""URL schemes and ports (v0.4).

Security properties tested here:
- host_in accepts only http and https by default. Any other scheme (ftp, gopher, file,
  javascript, ws, ...) makes the argument uncheckable: the WHOLE request is denied, for
  allow rules (no protocol smuggling to an allowed host) and deny rules (no dodging).
- "schemes" on the condition replaces the list (["https"] also refuses plain http);
  it is refused on any other op and must be well-formed.
- Every URL-shaped check refuses a port outside 1-65535 or with a leading zero.
- W017 warns when two host_in conditions on one argument accept different schemes.
- The reason never echoes the URL.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from warden.check import check_policy
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, EvaluationResult, Rule
from warden.policy import Policy


def host_rule(effect: str, hosts: list[str], rule_id: str = "r", **extra: Any) -> dict[str, Any]:
    return {
        "id": rule_id,
        "tool": "fetch",
        "effect": effect,
        "when": [{"arg": "url", "op": "host_in", "value": hosts, **extra}],
    }


ALLOW_OURS = host_rule("allow", [".example.com"])
DENY_EVIL = host_rule("deny", ["evil.net"], "block")
ALLOW_ALL = {"id": "allow-all", "tool": "fetch", "effect": "allow"}


def rules(*items: dict[str, Any]) -> tuple[Rule, ...]:
    return Policy.model_validate_json(json.dumps({"rules": list(items)})).rules


def ask(policy_rules: tuple[Rule, ...], url: object) -> EvaluationResult:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "fetch", "arguments": {"url": url}}
    )
    return evaluate(request, policy_rules)


# --- Schemes ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "ftp://api.example.com/x",
        "gopher://api.example.com:25/_HELO",
        "file://api.example.com/etc/passwd",
        "javascript://api.example.com/%0aalert(1)",
        "ws://api.example.com/",
        "wss://api.example.com/",
        "git+ssh://api.example.com/repo",
        "http.evil://api.example.com/",
    ],
)
def test_other_schemes_to_an_allowed_host_deny_the_whole_request(url: str) -> None:
    result = ask(rules(ALLOW_OURS), url)
    assert result.decision is Decision.DENY
    assert (
        result.reason == "argument 'url' could not be checked (URL scheme not accepted by the rule)"
    )
    assert "example" not in result.reason


@pytest.mark.parametrize("url", ["ftp://evil.net/", "gopher://evil.net/", "FILE://evil.net/"])
def test_odd_scheme_cant_dodge_a_deny_rule(url: str) -> None:
    assert ask(rules(DENY_EVIL, ALLOW_ALL), url).decision is Decision.DENY


@pytest.mark.parametrize("url", ["ftp://good.org/", "ws://good.org/"])
def test_odd_scheme_denies_even_for_hosts_the_deny_rule_doesnt_name(url: str) -> None:
    # Uncheckable, not "condition false": the same answer for every effect.
    assert ask(rules(DENY_EVIL, ALLOW_ALL), url).decision is Decision.DENY


@pytest.mark.parametrize(
    "url", ["http://api.example.com/", "https://api.example.com/", "HTTPS://api.example.com/"]
)
def test_http_and_https_any_case_still_work(url: str) -> None:
    assert ask(rules(ALLOW_OURS), url).decision is Decision.ALLOW


def test_schemes_replaces_the_default_list() -> None:
    policy = rules(host_rule("allow", [".example.com"], schemes=["https", "wss"]))
    assert ask(policy, "https://api.example.com/").decision is Decision.ALLOW
    assert ask(policy, "WSS://api.example.com/").decision is Decision.ALLOW
    assert ask(policy, "http://api.example.com/").decision is Decision.DENY
    assert ask(policy, "ws://api.example.com/").decision is Decision.DENY
    assert ask(policy, "wss://evil.net/").decision is Decision.DENY


def test_custom_scheme_with_symbols() -> None:
    policy = rules(host_rule("allow", ["git.example.com"], schemes=["git+ssh"]))
    assert ask(policy, "git+ssh://git.example.com/repo").decision is Decision.ALLOW
    assert ask(policy, "https://git.example.com/repo").decision is Decision.DENY


def test_otherwise_rule_with_odd_scheme_denies_not_otherwise() -> None:
    rule = {**ALLOW_OURS, "otherwise": "require_approval"}
    assert ask(rules(rule), "ftp://evil.net/").decision is Decision.DENY
    assert ask(rules(rule), "https://evil.net/").decision is Decision.REQUIRE_APPROVAL


@pytest.mark.parametrize(
    "schemes",
    [
        None,
        [],
        ["HTTPS"],
        ["https", "https"],
        ["1http"],
        ["ht tp"],
        ["https:"],
        [""],
        ["a" * 33],
        ["s" + str(i) for i in range(11)],
        "https",
        [5],
    ],
)
def test_bad_schemes_are_load_errors(schemes: object) -> None:
    with pytest.raises(ValidationError):
        rules(host_rule("allow", ["example.com"], schemes=schemes))


@pytest.mark.parametrize(
    "cond",
    [
        {"arg": "url", "op": "eq", "value": "https://x.com/", "schemes": ["https"]},
        {"arg": "url", "op": "startswith", "value": "https://x.com/", "schemes": ["https"]},
        {"arg": "url", "op": "exists", "schemes": ["https"]},
    ],
)
def test_schemes_only_on_host_in(cond: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="'schemes' only works with 'host_in'"):
        rules({"id": "r", "tool": "fetch", "effect": "deny", "when": [cond]})


# --- Ports -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com:0/",
        "https://api.example.com:00/",
        "https://api.example.com:0443/",
        "https://api.example.com:080/",
        "https://api.example.com:65536/",
        "https://api.example.com:99999/",
        "https://api.example.com:4294967739/",
        "https://api.example.com:٤٤٣/",  # Arabic-Indic digits
        "https://api.example.com:²/",  # superscript two
        "https://[::1]:0/",
        "https://[2001:db8::1]:99999/",
        "https://[2001:db8::1]:0443/",
    ],
)
def test_bad_ports_are_refused(url: str) -> None:
    allow_ip = host_rule("allow", [".example.com"], "a")
    result = ask(rules(allow_ip), url)
    assert result.decision is Decision.DENY
    assert "could not be checked" in result.reason


@pytest.mark.parametrize("url", ["https://api.example.com:0/", "https://evil.net:99999/"])
def test_bad_ports_are_refused_by_text_url_ops_too(url: str) -> None:
    deny_text = {
        "id": "t",
        "tool": "fetch",
        "effect": "deny",
        "when": [{"arg": "url", "op": "startswith", "value": "https://evil.net/"}],
    }
    result = ask(rules(deny_text, ALLOW_ALL), url)
    assert result.decision is Decision.DENY
    assert "could not be checked" in result.reason


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com:1/",
        "https://api.example.com:443/",
        "https://api.example.com:8443/",
        "https://api.example.com:65535/",
    ],
)
def test_good_ports_pass(url: str) -> None:
    assert ask(rules(ALLOW_OURS), url).decision is Decision.ALLOW


def test_good_port_on_ipv6_passes() -> None:
    policy = rules(host_rule("allow", ["example.com"]), ALLOW_ALL)
    assert ask(policy, "https://[2001:db8::1]:8443/").decision is Decision.ALLOW


# --- warden check ----------------------------------------------------------------------


def codes(tmp_path: Path, *items: dict[str, Any]) -> list[str]:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": list(items)}))
    report = check_policy(path)
    assert report.errors == []
    return [w.split(":")[0] for w in report.warnings]


def test_w017_different_schemes_on_one_argument(tmp_path: Path) -> None:
    a = host_rule("allow", ["a.example.com"], "a", schemes=["https"])
    b = host_rule("allow", ["b.example.com"], "b")
    assert "W017" in codes(tmp_path, a, b)


def test_no_w017_for_same_schemes_or_different_arguments(tmp_path: Path) -> None:
    a = host_rule("allow", ["a.example.com"], "a")
    b = host_rule("allow", ["b.example.com"], "b", schemes=["https", "http"])
    assert "W017" not in codes(tmp_path, a, b)
    c = host_rule("allow", ["a.example.com"], "c", schemes=["https"])
    c["when"][0]["arg"] = "other"
    assert "W017" not in codes(tmp_path, a, c)
    d = {**host_rule("allow", ["a.example.com"], "d", schemes=["https"]), "tool": "other"}
    assert "W017" not in codes(tmp_path, a, d)


def test_w004_takes_schemes_into_account(tmp_path: Path) -> None:
    a = host_rule("allow", ["a.example.com"], "a")
    same = host_rule("allow", ["a.example.com"], "b")
    assert "W004" in codes(tmp_path, a, same)
    other = host_rule("allow", ["a.example.com"], "b", schemes=["https"])
    assert "W004" not in codes(tmp_path, a, other)
