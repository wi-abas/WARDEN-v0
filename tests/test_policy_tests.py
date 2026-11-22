"""`warden test`: policy tests (example requests with expected decisions)."""

import json
from pathlib import Path
from typing import Any

import pytest

from warden.cli import main
from warden.models import Decision
from warden.policy import parse_policy
from warden.policy_tests import PolicyCase, PolicyTestError, load_tests, run_case

ROOT = Path(__file__).resolve().parent.parent

POLICY = {
    "rules": [
        {
            "id": "small",
            "tool": "pay",
            "effect": "allow",
            "when": [{"arg": "amount", "op": "lte", "value": 100}],
        },
        {
            "id": "big",
            "tool": "pay",
            "effect": "require_approval",
            "when": [{"arg": "amount", "op": "gt", "value": 100}],
            "message": "Big payments need approval",
        },
    ]
}


def case(**fields: Any) -> PolicyCase:
    base: dict[str, Any] = {"name": "c", "request": {"tool": "pay", "arguments": {"amount": 5}}}
    return PolicyCase.model_validate({**base, **fields})


def write(tmp_path: Path, cases: list[dict[str, Any]], **extra: Any) -> Path:
    (tmp_path / "policy.json").write_text(json.dumps(POLICY))
    path = tmp_path / "tests.json"
    path.write_text(json.dumps({"policy": "policy.json", "cases": cases, **extra}))
    return path


PAY_SMALL = {"name": "small", "request": {"tool": "pay", "arguments": {"amount": 5}}}
PAY_BIG = {"name": "big", "request": {"tool": "pay", "arguments": {"amount": 500}}}


def test_the_shipped_example_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test", str(ROOT / "examples" / "policy-tests.json")]) == 0
    assert "0 failed" in capsys.readouterr().out


def test_pass_and_fail(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(
        tmp_path,
        [
            {**PAY_SMALL, "expect": "allow", "rule": "small"},
            {**PAY_BIG, "expect": "allow"},  # wrong on purpose
        ],
    )
    assert main(["test", str(path)]) == 1
    out = capsys.readouterr().out
    assert "PASS  small" in out
    assert "FAIL  big: expected allow, got require_approval" in out
    assert "1 passed, 1 failed" in out


def test_rule_and_reason_are_checked() -> None:
    policy = parse_policy(json.dumps(POLICY))
    big = {"request": PAY_BIG["request"], "expect": "require_approval"}
    assert run_case(policy, case(**big, rule="big", reason="Big payments need approval")) is None
    assert "expected rule 'small', got 'big'" in str(run_case(policy, case(**big, rule="small")))
    assert "expected reason 'x'" in str(run_case(policy, case(**big, reason="x")))
    # rule: null means "no rule matched"
    unknown = {"request": {"tool": "other"}, "expect": "deny"}
    assert run_case(policy, case(**unknown, rule=None)) is None
    assert run_case(policy, case(**big, rule=None)) is not None


def test_invalid_requests_count_as_deny() -> None:
    policy = parse_policy(json.dumps(POLICY))
    bad = {"request": {"tool": "Bad Tool!"}}
    assert run_case(policy, case(**bad, expect="deny")) is None
    assert run_case(policy, case(**bad, expect="deny", rule=None)) is None
    problem = run_case(policy, case(**bad, expect="allow"))
    assert problem is not None and problem.startswith("rejected as invalid input")
    # Invalid input never matched a rule, so naming one fails.
    assert run_case(policy, case(**bad, expect="deny", rule="small")) is not None
    assert run_case(policy, case(**bad, expect="deny", reason="x")) is not None


def test_requests_go_through_json_like_the_api() -> None:
    policy = parse_policy(json.dumps(POLICY))
    # true is never the number 1, exactly as on the wire.
    sneaky = {"request": {"tool": "pay", "arguments": {"amount": True}}}
    assert run_case(policy, case(**sneaky, expect=Decision.ALLOW)) is not None


def test_policy_override(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, [{**PAY_SMALL, "expect": "deny"}])
    empty = tmp_path / "deny-all.json"
    empty.write_text(json.dumps({"rules": [{"id": "x", "tool": "x", "effect": "deny"}]}))
    assert main(["test", str(path), "--policy", str(empty)]) == 0
    assert "deny-all.json" in capsys.readouterr().out


def test_missing_policy_field(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"cases": [{**PAY_SMALL, "expect": "allow"}]}))
    assert main(["test", str(path)]) == 2
    assert 'has no "policy"' in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "isn't valid JSON"),
        ('{"cases": [], "cases": []}', "duplicate key"),
        ('{"cases": []}', "cases"),
        ('{"cases": [{"name": "a"}]}', "cases.0"),
        ('{"cases": [], "extra": 1}', "extra"),
    ],
)
def test_bad_test_files(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "t.json"
    path.write_text(content)
    with pytest.raises(PolicyTestError, match=message):
        load_tests(path)


def test_duplicate_case_names(tmp_path: Path) -> None:
    path = write(tmp_path, [{**PAY_SMALL, "expect": "allow"}, {**PAY_SMALL, "expect": "deny"}])
    with pytest.raises(PolicyTestError, match="same name"):
        load_tests(path)


def test_unreadable_and_huge_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(PolicyTestError, match="can't read"):
        load_tests(tmp_path / "missing.json")
    import warden.policy_tests as module

    monkeypatch.setattr(module, "MAX_TEST_FILE_BYTES", 5)
    big = tmp_path / "big.json"
    big.write_text("x" * 6)
    with pytest.raises(PolicyTestError, match="larger than"):
        load_tests(big)


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (None, "can't read policy"),
        ('{"rules": [{"id": "x"}]}', "policy"),
        ('{"rules": [], "rules": []}', "duplicate key"),
    ],
)
def test_broken_policy_is_an_error_not_deny_all(
    tmp_path: Path, policy: str | None, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, [{**PAY_SMALL, "expect": "deny"}])
    target = tmp_path / "policy.json"
    if policy is None:
        target.unlink()
    else:
        target.write_text(policy)
    # A broken policy denies everything on the server; a test run must say so, not pass.
    assert main(["test", str(path)]) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("name", ["", "a\nFAKE PASS", "\x1b[2Jcleared", "x\u202eevil", "x" * 201])
def test_case_names_are_safe_to_print(tmp_path: Path, name: str) -> None:
    """Names are printed to terminals and CI logs: no newlines, escapes or bidi tricks."""
    path = write(tmp_path, [{**PAY_SMALL, "name": name, "expect": "allow"}])
    with pytest.raises(PolicyTestError, match="name"):
        load_tests(path)
