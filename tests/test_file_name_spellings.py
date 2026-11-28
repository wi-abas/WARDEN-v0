"""File names a file system reads differently from their letters can't dodge a rule.

Windows drops trailing dots and spaces (".env." opens ".env"), reads "name::$DATA" as the
file "name", and has short names ("ENV~1"); "dir/" is "dir" everywhere. For startswith,
endswith and eq/in, Warden compares the text as written AND as a file system reads it:
if the answers differ, the text can't be checked and the whole request is denied. When
they agree nothing changes, so ordinary paths and text keep working."""

import json

import pytest

from warden.engine import _file_system_reading, evaluate
from warden.models import ActionRequest, Decision, Rule


def rule(rule_id: str, effect: str, *when: dict[str, object]) -> Rule:
    body = {"id": rule_id, "tool": "read_file", "effect": effect, "when": list(when)}
    return Rule.model_validate_json(json.dumps(body))


RULES = [
    rule("workspace", "allow", {"arg": "path", "op": "startswith", "value": "/workspace/"}),
    rule("no-env", "deny", {"arg": "path", "op": "endswith", "value": ".env"}),
    rule("no-ssh", "deny", {"arg": "path", "op": "endswith", "value": "/.ssh"}),
    rule("no-secret", "deny", {"arg": "path", "op": "startswith", "value": "/workspace/secret/"}),
    rule("no-key", "deny", {"arg": "path", "op": "eq", "value": "/workspace/id_rsa"}),
]
FILE_NAME = "a file name read differently"


def decide(path: str, rules: list[Rule] = RULES) -> tuple[Decision, str]:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "read_file", "arguments": {"path": path}}
    )
    result = evaluate(request, rules)
    return result.decision, result.reason


@pytest.mark.parametrize(
    "path",
    [
        "/workspace/.env.",
        "/workspace/.env..",
        "/workspace/.env. .",
        "/workspace/.env::$DATA",
        "/workspace/.env:stream",
        "/workspace/.env:stream:$DATA",
        "/workspace/.env/",
        "/workspace/.ssh/",
        "/workspace/.ssh//",
        "/workspace/.ssh\\",
        "/workspace/secret./x",
        "/workspace/secret /x",
        "/workspace/secret:x/y",
        "/workspace/id_rsa.",
        "/workspace/id_rsa/",
        "/workspace/id_rsa::$DATA",
        ".env.",
        ".env::$DATA",
    ],
)
def test_file_system_spellings_are_denied(path: str) -> None:
    decision, reason = decide(path)
    assert decision is Decision.DENY
    assert FILE_NAME in reason or "not a clean path" in reason
    assert path not in reason  # the reason never echoes the argument


@pytest.mark.parametrize(
    "path",
    ["/workspace/ENV~1", "/workspace/PROGRA~1/x", "/workspace/SECRET~12.TXT", "ENV~1", "C:\\A~1"],
)
def test_short_names_are_uncheckable(path: str) -> None:
    decision, reason = decide(path)
    assert decision is Decision.DENY
    assert FILE_NAME in reason


@pytest.mark.parametrize(
    "path",
    [
        "/workspace/src/",
        "/workspace/a.txt",
        "/workspace/.env.example",
        "/workspace/notes: today/x",
        "/workspace/v1.2/file",
        "/workspace/a~b",
        "/workspace/backup~",
        "/workspace/file~1extra",
        "/workspace/~/x",
        "/workspace/TOOLONGNAME~1",
    ],
)
def test_ordinary_paths_still_work(path: str) -> None:
    assert decide(path) == (Decision.ALLOW, "matched rule 'workspace'")


def test_plain_names_still_match_their_rules() -> None:
    assert decide("/workspace/.env") == (Decision.DENY, "matched rule 'no-env'")
    assert decide("/workspace/.ssh") == (Decision.DENY, "matched rule 'no-ssh'")
    assert decide("/workspace/id_rsa") == (Decision.DENY, "matched rule 'no-key'")
    assert decide("/workspace/secret/x") == (Decision.DENY, "matched rule 'no-secret'")


def test_values_that_end_the_same_way_agree() -> None:
    rules = [
        rule("dir", "allow", {"arg": "path", "op": "eq", "value": "/workspace/"}),
        rule("note", "allow", {"arg": "path", "op": "in", "value": ["Done.", "a/b: ok"]}),
        rule("drive", "allow", {"arg": "path", "op": "eq", "value": "C:/data/x"}),
        rule("root", "allow", {"arg": "path", "op": "eq", "value": "/"}),
    ]
    assert decide("/workspace/", rules) == (Decision.ALLOW, "matched rule 'dir'")
    assert decide("Done.", rules) == (Decision.ALLOW, "matched rule 'note'")
    assert decide("a/b: ok", rules) == (Decision.ALLOW, "matched rule 'note'")
    assert decide("C:/data/x", rules) == (Decision.ALLOW, "matched rule 'drive'")
    assert decide("/", rules) == (Decision.ALLOW, "matched rule 'root'")


def test_one_dot_away_from_a_listed_value_is_uncheckable() -> None:
    # "Done" isn't "Done." as text, but a file system reads them alike: fail closed.
    rules = [rule("note", "allow", {"arg": "path", "op": "in", "value": ["Done."]})]
    decision, reason = decide("Done", rules)
    assert decision is Decision.DENY and FILE_NAME in reason


def test_neq_and_ignore_case_use_both_readings() -> None:
    rules = [
        rule("all", "allow"),
        rule(
            "not-env",
            "deny",
            {"arg": "path", "op": "endswith", "value": ".ENV", "ignore_case": True},
        ),
        rule("only-x", "deny", {"arg": "path", "op": "neq", "value": "x"}),
    ]
    assert decide("/w/.env.", rules)[1].endswith("':' stream, or ABC~1)")
    assert decide("x.", rules)[0] is Decision.DENY
    assert decide("x", rules) == (Decision.ALLOW, "matched rule 'all'")


def test_urls_keep_their_own_checks() -> None:
    rules = [
        rule("site", "allow", {"arg": "path", "op": "startswith", "value": "https://good.com/"}),
        rule("page", "deny", {"arg": "path", "op": "eq", "value": "https://good.com/a"}),
    ]
    assert decide("https://good.com/a.", rules) == (Decision.ALLOW, "matched rule 'site'")
    assert decide("https://good.com/a:b", rules) == (Decision.ALLOW, "matched rule 'site'")


@pytest.mark.parametrize(
    ("text", "final_slash", "reading"),
    [
        (".env.", False, ".env"),
        (".env .", False, ".env"),
        (".env::$DATA", False, ".env"),
        ("a:b c", False, "a:b c"),
        ("C:/x.", False, "C:/x"),
        ("C:", False, "C:"),
        ("D:x", False, "D"),
        ("a./b./", False, "a/b/"),
        ("a./b./", True, "a/b"),
        ("a\\b\\", True, "a\\b"),
        ("/", True, "/"),
        ("..", False, ".."),
        ("x/./y", False, "x/./y"),
        ("x/ /y", False, "x/ /y"),
        ("plain", True, "plain"),
    ],
)
def test_file_system_reading(text: str, final_slash: bool, reading: str) -> None:
    assert _file_system_reading(text, final_slash) == reading
