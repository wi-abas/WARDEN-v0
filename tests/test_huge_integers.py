"""Integers longer than Python will parse (4300 digits): json.loads raises a plain
ValueError (not JSONDecodeError), which used to escape as a raw traceback."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY
from pydantic import ValidationError

from warden import cli
from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.check import check_policy
from warden.limits_cli import LimitsEditError, show
from warden.policy import EMPTY_POLICY, load_policy, parse_policy
from warden.policy_tests import PolicyTestError, load_policy_strict, load_tests

HUGE = "9" * 5000
RULE = '{"id": "r", "tool": "t", "effect": "deny", "when": [{"arg": "a", "op": "gt", "value": %s}]}'
POLICIES = [
    '{"rules": [' + RULE % HUGE + "]}",
    '{"rules": [' + RULE % ("-" + HUGE) + "]}",
    # A duplicate key behind the number: never accepted without the duplicate check.
    '{"rules": [], "rules": [' + RULE % HUGE + "]}",
    '{"rules": [], "limits": {"default": {"requests_per_minute": ' + HUGE + "}}}",
]


def test_the_parser_really_raises_a_plain_value_error() -> None:
    with pytest.raises(ValueError) as caught:
        json.loads(HUGE)
    assert not isinstance(caught.value, json.JSONDecodeError)


@pytest.fixture(params=POLICIES)
def policy(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(request.param)
    path.chmod(0o600)
    return path


def test_parse_policy_refuses_it_like_any_invalid_policy(policy: Path) -> None:
    with pytest.raises(ValidationError, match="too many digits") as caught:
        parse_policy(policy.read_text())
    assert HUGE not in str(caught.value)


def test_every_command_gives_a_clear_error(
    policy: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("warden.api.main", lambda s: pytest.fail("server started"))
    assert check_policy(policy).errors == ["file: a number has too many digits"]
    assert cli.main(["check", str(policy)]) == 1
    assert cli.main(["serve", "--policy", str(policy)]) == 2
    printed = "".join(capsys.readouterr())
    assert "too many digits" in printed and HUGE not in printed
    with pytest.raises(PolicyTestError, match="too many digits"):
        load_policy_strict(policy)
    with pytest.raises(LimitsEditError, match="invalid"):
        show(policy)


def test_server_loads_no_rules(policy: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert load_policy(policy) is EMPTY_POLICY
    assert "too many digits" in caplog.text and HUGE not in caplog.text


@pytest.mark.parametrize("arguments", ['{"n": %s}', '{"n": [{"x": -%s}]}', '{"n": %s, "n": 1}'])
def test_api_denies(arguments: str, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    body = '{"agent_id": "a", "tool": "read_file", "arguments": ' + arguments % HUGE + "}"
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    response = TestClient(app).post(
        "/v1/evaluate", content=body, headers={"content-type": "application/json"}
    )
    answer: dict[str, Any] = response.json()
    assert 400 <= response.status_code < 500
    assert answer["decision"] == "deny"
    assert HUGE not in response.text and HUGE not in caplog.text


def test_duplicate_key_message_is_always_printable(tmp_path: Path) -> None:
    # A lone surrogate can't be printed: naming the key raw crashed `warden check`.
    path = tmp_path / "p.json"
    path.write_text('{"\\ud800": 1, "\\ud800": 2}')
    [error] = check_policy(path).errors
    assert error == "duplicate key '\\ud800' (one value would silently win)"
    error.encode("utf-8")


def test_policy_test_file_with_a_huge_number_is_a_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "tests.json"
    path.write_text('{"cases": [' + HUGE + "]}")
    with pytest.raises(PolicyTestError, match="too many digits"):
        load_tests(path)
