"""`warden check`: errors, each warning, exit codes, and the CLI."""

import json
from pathlib import Path
from typing import Any

import pytest

from warden.check import check_policy
from warden.cli import main
from warden.policy import DEFAULT_POLICY_PATH


def write(tmp_path: Path, policy: object) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(policy if isinstance(policy, str) else json.dumps(policy))
    return path


def r(id: str, tool: str, effect: str, *when: dict[str, Any]) -> dict[str, Any]:
    return {"id": id, "tool": tool, "effect": effect, "when": list(when)}


def codes(tmp_path: Path, policy: object) -> list[str]:
    return [w.split(":")[0] for w in check_policy(write(tmp_path, policy)).warnings]


# --- Errors ----------------------------------------------------------------------------


def test_default_policy_is_clean() -> None:
    report = check_policy(DEFAULT_POLICY_PATH)
    assert report.errors == [] and report.warnings == []
    assert report.rules == 4


def test_missing_file_is_an_error(tmp_path: Path) -> None:
    assert check_policy(tmp_path / "nope.json").errors == [
        "can't read " + str(tmp_path / "nope.json") + ": FileNotFoundError"
    ]


def test_invalid_rule_error_says_where(tmp_path: Path) -> None:
    report = check_policy(
        write(tmp_path, {"rules": [r("a", "t", "allow", {"arg": "x", "op": "regex", "value": 1})]})
    )
    assert len(report.errors) == 1
    assert report.errors[0].startswith("rule 'a' (rules.0).when.0.op:")


def test_error_location_names_the_rule_id(tmp_path: Path) -> None:
    bad = {"arg": "amount", "op": "lt", "value": "500"}  # text, not a number
    report = check_policy(
        write(
            tmp_path,
            {"rules": [r("ok", "t", "allow"), r("pay-small", "pay", "allow", bad)]},
        )
    )
    assert len(report.errors) == 1
    assert report.errors[0].startswith("rule 'pay-small' (rules.1).when.0")


@pytest.mark.parametrize(
    "rule",
    [
        {"id": "Not A Valid Id", "tool": "t", "effect": "maybe"},  # invalid id: not shown
        {"id": 5, "tool": "t", "effect": "maybe"},
        {"tool": "t", "effect": "maybe"},
        "not an object",
    ],
)
def test_error_location_without_a_usable_rule_id(tmp_path: Path, rule: object) -> None:
    report = check_policy(write(tmp_path, {"rules": [rule]}))
    assert report.errors and all(e.startswith("rules.0") for e in report.errors)
    assert "Not A Valid Id" not in " ".join(report.errors)


def test_describe_errors_without_rules_or_json() -> None:
    from pydantic import ValidationError

    from warden.policy import Policy, describe_errors

    for raw in ("{bad json", '{"rules": 5}', "[1]"):
        try:
            Policy.model_validate_json(raw)
        except ValidationError as exc:
            assert not any("rule '" in e for e in describe_errors(exc, raw))


def test_errors_never_echo_file_contents(tmp_path: Path) -> None:
    canary = "sk-live-FAKE-123"
    report = check_policy(
        write(tmp_path, {"rules": [{"id": canary, "tool": "t", "effect": "allow"}]})
    )
    assert report.errors and canary not in " ".join(report.errors)


# --- Warnings --------------------------------------------------------------------------

EVIL = {"arg": "to", "op": "startswith", "value": "evil"}


def test_w001_deny_list_without_argument_list(tmp_path: Path) -> None:
    rules = [r("allow", "send_email", "allow"), r("block", "send_email", "deny", EVIL)]
    assert codes(tmp_path, {"rules": rules}) == ["W001"]
    with_spec = {"tools": {"send_email": {"arguments": ["to"]}}, "rules": rules}
    assert codes(tmp_path, with_spec) == []


def test_w001_not_raised_without_an_allow(tmp_path: Path) -> None:
    # Nothing is allowed for the tool anyway, so there's nothing to slip past.
    assert codes(tmp_path, {"rules": [r("block", "send_email", "deny", EVIL)]}) == []


def test_w002_no_rules(tmp_path: Path) -> None:
    assert codes(tmp_path, {"rules": []}) == ["W002"]


def test_w003_dead_rule(tmp_path: Path) -> None:
    rules = [r("allow-delete", "delete_file", "allow"), r("block-delete", "delete_file", "deny")]
    warnings = check_policy(write(tmp_path, {"rules": rules})).warnings
    assert warnings == [
        'W003: rule "allow-delete" can never apply: "block-delete" always gives deny'
        " for delete_file."
    ]


def test_w003_conditional_stricter_rule_is_not_dead(tmp_path: Path) -> None:
    rules = [r("allow", "t", "allow"), r("block", "t", "deny", EVIL)]
    assert "W003" not in codes(tmp_path, {"tools": {"t": {"arguments": ["to"]}}, "rules": rules})


def test_w004_duplicate(tmp_path: Path) -> None:
    gt = {"arg": "amount", "op": "gt", "value": 5}
    rules = [r("a", "t", "deny", gt), r("b", "t", "deny", gt)]
    assert codes(tmp_path, {"rules": rules}) == ["W004"]


def test_w005_path_prefix(tmp_path: Path) -> None:
    bad = {"arg": "path", "op": "startswith", "value": "/data"}
    good = {"arg": "path", "op": "startswith", "value": "/data/"}
    assert codes(tmp_path, {"rules": [r("a", "t", "allow", bad)]}) == ["W005"]
    assert codes(tmp_path, {"rules": [r("a", "t", "allow", good)]}) == []


def test_w006_argument_list_without_rules(tmp_path: Path) -> None:
    policy = {"tools": {"ping": {"arguments": []}}, "rules": [r("a", "t", "allow")]}
    assert codes(tmp_path, policy) == ["W006"]


def test_w007_condition_on_unlisted_argument(tmp_path: Path) -> None:
    typo = {"arg": "reciepient", "op": "eq", "value": "x"}
    policy = {"tools": {"t": {"arguments": ["recipient"]}}, "rules": [r("a", "t", "allow", typo)]}
    assert codes(tmp_path, policy) == ["W007"]


# --- CLI -------------------------------------------------------------------------------


def test_cli_clean_policy_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(DEFAULT_POLICY_PATH)]) == 0
    assert "0 errors, 0 warnings." in capsys.readouterr().out


def test_cli_errors_exit_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(write(tmp_path, "not json"))]) == 1
    assert "deny everything" in capsys.readouterr().out


@pytest.mark.parametrize(("flags", "code"), [([], 0), (["--strict"], 1)])
def test_cli_warnings_and_strict(tmp_path: Path, flags: list[str], code: int) -> None:
    path = write(tmp_path, {"rules": []})
    assert main(["check", str(path), *flags]) == code


def test_check_does_not_start_the_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import warden.api

    monkeypatch.setattr(warden.api, "main", lambda: pytest.fail("server started"))
    main(["check", str(DEFAULT_POLICY_PATH)])


def test_w004_not_raised_when_only_ignore_case_differs(tmp_path: Path) -> None:
    a = {"arg": "a", "op": "eq", "value": "x"}
    b = {**a, "ignore_case": True}
    policy = {
        "tools": {"t": {"arguments": ["a"]}},
        "rules": [r("a", "t", "deny", a), r("b", "t", "deny", b)],
    }
    assert codes(tmp_path, policy) == []


@pytest.mark.parametrize("op", ["neq", "missing"])
def test_w010_allow_everything_except(tmp_path: Path, op: str) -> None:
    cond = {"arg": "to", "op": op, **({"value": "x"} if op == "neq" else {})}
    policy = {"tools": {"t": {"arguments": ["to"]}}, "rules": [r("a", "t", "allow", cond)]}
    assert codes(tmp_path, policy) == ["W010"]


def test_w010_not_raised_for_deny_rules(tmp_path: Path) -> None:
    cond = {"arg": "to", "op": "missing"}
    policy = {"tools": {"t": {"arguments": ["to"]}}, "rules": [r("a", "t", "deny", cond)]}
    assert codes(tmp_path, policy) == []


def test_w011_url_prefix_without_slash_after_host(tmp_path: Path) -> None:
    def policy(value: str) -> dict[str, Any]:
        cond = {"arg": "url", "op": "startswith", "value": value}
        return {"tools": {"t": {"arguments": ["url"]}}, "rules": [r("a", "t", "allow", cond)]}

    assert codes(tmp_path, policy("https://api.example.com")) == ["W011"]
    assert codes(tmp_path, policy("https://api.example.com/")) == []
    assert codes(tmp_path, policy("https://api.example.com/v1")) == []


def test_w003_not_raised_for_equally_strict_rules(tmp_path: Path) -> None:
    # An unconditional deny doesn't make a conditional deny "dead": same strictness.
    cond = {"arg": "a", "op": "eq", "value": "x"}
    policy = {
        "tools": {"t": {"arguments": ["a"]}},
        "rules": [r("always", "t", "deny"), r("sometimes", "t", "deny", cond)],
    }
    assert codes(tmp_path, policy) == []


@pytest.mark.parametrize(
    ("arg", "value", "expected"),
    [
        ("path", "workspace", ["W005"]),
        ("file_path", "workspace", ["W005"]),
        ("x", "src/app", ["W005"]),
        ("x", "./data", ["W005"]),
        ("path", "workspace/", []),
        ("x", "workspace", []),
        ("x", "git log a/b", []),
        ("x", "image/", []),
        ("x", "https://x.com/a", []),
        ("x", "me@x.com/a", []),
    ],
)
def test_w005_relative_path_prefix(
    tmp_path: Path, arg: str, value: str, expected: list[str]
) -> None:
    cond = {"arg": arg, "op": "startswith", "value": value}
    assert codes(tmp_path, {"rules": [r("a", "t", "allow", cond)]}) == expected


def blocks(op: str, arg: str, value: Any, **extra: Any) -> dict[str, Any]:
    cond = {"arg": arg, "op": op, "value": value, **extra}
    return {
        "tools": {"t": {"arguments": [arg]}},
        "rules": [r("all", "t", "allow"), r("block", "t", "deny", cond)],
    }


@pytest.mark.parametrize(
    ("op", "arg", "value", "expected"),
    [
        ("eq", "host", "evil.com", ["W018"]),
        ("endswith", "x", ".evil.com", ["W018"]),
        ("in", "x", ["ok", "evil.com"], ["W018"]),
        ("contains", "x", "evil.com", ["W018"]),
        ("eq", "x", "v1.2.3", []),
        ("eq", "x", "notes.txt", []),
        ("eq", "path", "a.evil", []),
        ("eq", "x", "evil", []),
        ("neq", "x", "evil.com", []),
    ],
)
def test_w018_host_name_compared_case_sensitively(
    tmp_path: Path, op: str, arg: str, value: Any, expected: list[str]
) -> None:
    assert codes(tmp_path, blocks(op, arg, value)) == expected


def test_w018_not_raised_when_it_cannot_matter(tmp_path: Path) -> None:
    assert codes(tmp_path, blocks("eq", "x", "evil.com", ignore_case=True)) == []
    only_deny = blocks("eq", "x", "evil.com")
    only_deny["rules"] = only_deny["rules"][1:]
    assert codes(tmp_path, only_deny) == []  # dodging it lands on "no matching rule"


@pytest.mark.parametrize(
    ("effect", "arg", "value", "expected"),
    [
        ("allow", "to", "mycompany.com", ["W019"]),
        ("allow", "to", "@mycompany.com", ["W008"]),
        ("allow", "host", ".mycompany.com", []),
        ("allow", "x", "report.pdf", []),
        ("allow", "filename", "a.report", []),
        ("deny", "to", "mycompany.com", []),
    ],
)
def test_w019_allowed_domain_without_a_boundary(
    tmp_path: Path, effect: str, arg: str, value: str, expected: list[str]
) -> None:
    cond = {"arg": arg, "op": "endswith", "value": value}
    policy = {"tools": {"t": {"arguments": [arg]}}, "rules": [r("a", "t", effect, cond)]}
    assert codes(tmp_path, policy) == expected


def test_w020_tool_names_differing_only_in_case(tmp_path: Path) -> None:
    policy = {
        "rules": [r("a", "getIssue", "allow"), r("b", "getissue", "deny")],
        "tools": {"GetIssue": {"arguments": []}},
    }
    assert codes(tmp_path, policy).count("W020") == 1
    report = check_policy(write(tmp_path, policy))
    [warning] = [w for w in report.warnings if w.startswith("W020")]
    assert '"GetIssue", "getIssue", "getissue"' in warning


def test_w020_not_raised_for_one_spelling(tmp_path: Path) -> None:
    policy = {"rules": [r("a", "getIssue", "allow"), r("b", "getIssue", "deny")]}
    assert "W020" not in codes(tmp_path, policy)
