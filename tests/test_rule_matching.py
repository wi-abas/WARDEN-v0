"""Text that a rule could read differently from the tool that receives it."""

import json
from typing import Any

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import parse_policy


def ask(rules: list[dict[str, Any]], value: Any) -> Decision:
    policy = parse_policy(json.dumps({"rules": rules}))
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "t", "arguments": {"x": value}}
    )
    return evaluate(request, policy.rules).decision


def allow(op: str, value: object, **extra: object) -> list[dict[str, Any]]:
    when = [{"arg": "x", "op": op, "value": value, **extra}]
    return [{"id": "rule", "tool": "t", "effect": "allow", "when": when}]


def deny(op: str, value: object, **extra: object) -> list[dict[str, Any]]:
    """Allow everything except what the condition matches."""
    return [
        {"id": "all", "tool": "t", "effect": "allow"},
        {**allow("eq", "x")[0], "effect": "deny", "when": allow(op, value, **extra)[0]["when"]},
    ]


# --- ignore_case: letters that only some software makes equal ---------------------------

# Rule, and a value that some software (not all) reads as matching it.
AMBIGUOUS: list[tuple[str, object, str]] = [
    ("endswith", "@business.com", "eve@busineß.com"),
    ("endswith", "@business.com", "eve@busineẞ.com"),
    ("eq", "boss@x.com", "boß@x.com"),
    ("in", ["boss@x.com"], "boß@x.com"),
    ("startswith", "https://business.com/", "https://busineß.com/"),
    ("eq", "straße", "STRASSE"),
    ("eq", "οδοσ", "οδος"),  # final sigma
    ("eq", "istanbul", "İstanbul"),  # dotted capital i
    ("eq", "admin", "admın"),  # dotless i: upper() gives ADMIN
    ("startswith", "xi", "xİ"),
    ("eq", "lock", "locK"),  # Kelvin sign
    ("eq", "loss", "loſs"),  # long s
    ("eq", "file", "ﬁle"),  # fi ligature
]


@pytest.mark.parametrize(("op", "rule_value", "value"), AMBIGUOUS)
def test_ambiguous_case_folds_never_allow(op: str, rule_value: object, value: str) -> None:
    assert ask(allow(op, rule_value, ignore_case=True), value) == Decision.DENY


@pytest.mark.parametrize(
    ("op", "rule_value", "value"),
    [
        *AMBIGUOUS,
        ("contains", "pass", "the paß word"),
        ("contains", ["zzz", "kill"], "kıll it"),
        ("contains", "kill", "KİLL it"),
    ],
)
def test_ambiguous_case_folds_never_dodge_a_deny_rule(
    op: str, rule_value: object, value: str
) -> None:
    assert ask(deny(op, rule_value, ignore_case=True), value) == Decision.DENY


def test_an_ambiguous_neq_is_denied() -> None:
    rules = allow("neq", "boss", ignore_case=True)
    assert ask(rules, "boß") == Decision.DENY
    assert ask(rules, "ann") == Decision.ALLOW


@pytest.mark.parametrize("value", ["5 K", "a;b", "a`b"])
def test_characters_that_normalize_into_ascii_are_refused(value: str) -> None:
    # Kelvin sign, Greek question mark (";") and Greek varia ("`"): NFC turns them into
    # ASCII, so a rule would compare something the tool never received.
    assert ask(deny("eq", "something"), value) == Decision.DENY


@pytest.mark.parametrize(
    ("rule_value", "value"),
    [
        ("straße", "STRAßE"),
        ("Zürich", "zÜRICH"),
        ("привет", "ПРИВЕТ"),
        ("日本語", "日本語"),
        ("\u0130zmir", "\u0130ZMIR"),
        ("café", "CAFÉ"),
        ("ΑΘΗΝΑ", "αθηνα"),
    ],
)
def test_ordinary_text_still_ignores_case(rule_value: str, value: str) -> None:
    assert ask(allow("eq", rule_value, ignore_case=True), value) == Decision.ALLOW


@pytest.mark.parametrize("value", ["Straße", "İstanbul", "οδός", "ışık", "naïve"])
def test_special_letters_are_fine_where_they_decide_nothing(value: str) -> None:
    assert ask(deny("contains", ["rm -rf", "mkfs"], ignore_case=True), value) == Decision.ALLOW
    assert ask(deny("eq", "other", ignore_case=True), value) == Decision.ALLOW


def test_an_exact_choice_wins_over_an_ambiguous_one() -> None:
    rules = allow("in", ["strasse", "straße"], ignore_case=True)
    assert ask(rules, "Straße") == Decision.ALLOW


# --- startswith: ".." always denies, also when the rule's prefix has no "/" -------------

DOT_DOT = [
    "workspace/../x",
    "workspace/../../etc/passwd",
    "workspace/a/..",
    "workspace\\..\\x",
    "workspace/.. /x",
    "workspace/.../x",
    "workspace/..;/x",
    "workspace/%2e%2e/x",
    "workspace/.%2E/x",
    "workspace%2f..%5cx",
    "workspace/%252e%252e/x",
    "../workspace",
    "..",
]


@pytest.mark.parametrize("value", DOT_DOT)
def test_dot_dot_denies_for_a_prefix_without_a_slash(value: str) -> None:
    assert ask(allow("startswith", "workspace"), value) == Decision.DENY
    assert ask(deny("startswith", "secret"), value) == Decision.DENY


@pytest.mark.parametrize(
    "value",
    ["wait...", "wait... and/or go", "wait for a..b", "wait/a..b/c", "wait/..a", "wait 5/6. ok"],
)
def test_harmless_dots_are_fine(value: str) -> None:
    assert ask(allow("startswith", "wait"), value) == Decision.ALLOW


def test_long_runs_of_dots_are_checked_quickly() -> None:
    assert ask(allow("startswith", "wait"), "wait/" + "." * 50_000 + "x") == Decision.ALLOW


# --- Hosts: characters that can't be in a host name --------------------------------------


@pytest.mark.parametrize("char", list(";'\"|^`{}<>,&*=$()!~+ "))
def test_illegal_host_characters_are_denied(char: str) -> None:
    # A loose URL parser (Node's url.parse) stops at the character and reaches evil.net.
    assert ask(allow("host_in", [".example.com"]), f"http://evil.net{char}.example.com/") == (
        Decision.DENY
    )
    assert ask(deny("host_in", [".evil.net"]), f"http://evil.net{char}x/") == Decision.DENY
    evil_text = deny("startswith", "http://evil.net/", ignore_case=True)
    assert ask(evil_text, f"http://evil.net{char}x/") == Decision.DENY


@pytest.mark.parametrize("host", ["[::1;x]", "[v1.x]", "[::1%25eth0]", "[fe80::1']"])
def test_odd_bracketed_hosts_are_denied(host: str) -> None:
    assert ask(deny("host_in", ["evil.net"]), f"http://{host}/") == Decision.DENY
    assert ask(deny("startswith", "http://evil.net/"), f"http://{host}/") == Decision.DENY


@pytest.mark.parametrize(
    "url",
    [
        "http://a-b_c.example.com:8080/x;y='z'",
        "http://EXAMPLE.com",
        "http://xn--strae-oqa.de/",
        "http://example.com?q=a;b",
        "http://example.com#a!b",
        "http://10.0.0.1/",
        "http://[::1]:8000/x",
        "http://[2001:DB8::ffff:1.2.3.4]/",
    ],
)
def test_legitimate_hosts_still_work(url: str) -> None:
    assert ask(deny("host_in", ["evil.net"]), url) == Decision.ALLOW
    assert ask(deny("startswith", "http://evil.net/"), url) == Decision.ALLOW


def test_international_hosts_still_work_in_text_rules() -> None:
    assert ask(allow("startswith", "https://例え.jp/"), "https://例え.jp/x") == Decision.ALLOW


# --- URL prefixes: dot segments in disguise ---------------------------------------------

API = "https://api.good.com/public/"


@pytest.mark.parametrize(
    "rest",
    [
        "..;/admin",
        "..;a=b/admin",
        ".;/admin",
        "..%3b/admin",
        "..%3Bx/admin",
        "%c0%ae%c0%ae/admin",  # overlong UTF-8 for "."
        "%e0%80%ae./admin",
        "%f0%80%80%ae./admin",
        "..%c0%af/admin",
        ".%00./admin",
        "..%00/admin",
        "a%0d%0ab",
        "a%7fb",
        "%u002e%u002e/admin",
        "%%32%65%%32%65/admin",
        ".%20./admin",
        "..%20/admin",
        "100%",
    ],
)
def test_disguised_dot_segments_are_denied(rest: str) -> None:
    assert ask(allow("startswith", API), API + rest) == Decision.DENY


@pytest.mark.parametrize(
    "rest",
    [
        "a;v=1/b",
        "a%3Bb",
        "a..;b/c",
        "my%20file.txt",
        "a%20/b",
        "caf%C3%A9",
        "caf%E9/x",
        "%E0%A4%A8%F0%9F%9A%80",
        "q?discount=100%&note=..;%00",
        "q#100%",
        "a;",
    ],
)
def test_ordinary_url_paths_still_work(rest: str) -> None:
    assert ask(allow("startswith", API), API + rest) == Decision.ALLOW


@pytest.mark.parametrize("path", ["/data/..;/x", "/data/.;a/x"])
def test_dot_segments_with_a_parameter_are_denied_in_paths(path: str) -> None:
    assert ask(allow("startswith", "/data/"), path) == Decision.DENY


def test_a_semicolon_in_a_file_name_is_fine() -> None:
    assert ask(allow("startswith", "/data/"), "/data/a;b/;c") == Decision.ALLOW
