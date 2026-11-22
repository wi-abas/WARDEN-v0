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
    assert report.errors[0].startswith("rules.0.when.0.op:")


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
