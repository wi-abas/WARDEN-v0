import json
import logging
from pathlib import Path

import pytest
from helpers import BASIC_POLICY

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import MAX_RULES, load_rules


def write_policy(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(content, encoding="utf-8")
    return path


def rule_json(rule_id: str = "allow-read", tool: str = "read_file", effect: str = "allow") -> dict:
    return {"id": rule_id, "tool": tool, "effect": effect}


def read_file_request() -> ActionRequest:
    return ActionRequest.model_validate({"agent_id": "agent-1", "tool": "read_file"})


# --- Good files --------------------------------------------------------------------


def test_valid_file_loads(tmp_path: Path) -> None:
    path = write_policy(tmp_path, json.dumps({"rules": [rule_json()]}))
    rules = load_rules(path)
    assert len(rules) == 1
    assert rules[0].id == "allow-read"
    assert rules[0].effect == Decision.ALLOW


def test_empty_rule_list_is_valid_and_denies_everything(tmp_path: Path) -> None:
    path = write_policy(tmp_path, '{"rules": []}')
    rules = load_rules(path)
    assert rules == ()
    assert evaluate(read_file_request(), rules).decision == Decision.DENY


def test_shipped_default_policy_loads() -> None:
    rules = load_rules(BASIC_POLICY)
    assert {rule.id for rule in rules} == {"allow-read", "approve-send", "block-delete"}


# --- Broken files: always no rules, so always deny -------------------------------

BROKEN_POLICIES = {
    "empty file": "",
    "not json": "this is not json",
    "truncated json": '{"rules": [',
    "not an object": "[]",
    "missing rules key": "{}",
    "rules not a list": '{"rules": "allow everything"}',
    "unknown effect": json.dumps({"rules": [rule_json(effect="maybe")]}),
    "bad tool name": json.dumps({"rules": [rule_json(tool="Read_File")]}),
    "bad rule id": json.dumps({"rules": [rule_json(rule_id="Bad Id")]}),
    "extra field in rule": json.dumps({"rules": [{**rule_json(), "priority": 1}]}),
    "extra top-level field": json.dumps({"rules": [], "default": "allow"}),
    "duplicate ids": json.dumps(
        {"rules": [rule_json(), rule_json(tool="send_email", effect="deny")]}
    ),
    "one bad rule among good ones": json.dumps(
        {"rules": [rule_json(), rule_json(rule_id="r2", effect="yes")]}
    ),
}


@pytest.mark.parametrize("content", BROKEN_POLICIES.values(), ids=BROKEN_POLICIES.keys())
def test_broken_file_gives_no_rules_and_denies(tmp_path: Path, content: str) -> None:
    rules = load_rules(write_policy(tmp_path, content))
    assert rules == ()
    assert evaluate(read_file_request(), rules).decision == Decision.DENY


def test_too_many_rules_is_rejected(tmp_path: Path) -> None:
    rules = [rule_json(rule_id=f"r{i}") for i in range(MAX_RULES + 1)]
    assert load_rules(write_policy(tmp_path, json.dumps({"rules": rules}))) == ()


def test_missing_file_gives_no_rules(tmp_path: Path) -> None:
    assert load_rules(tmp_path / "does-not-exist.json") == ()


def test_unreadable_bytes_give_no_rules(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(b"\xff\xfe\x00 not utf-8")
    assert load_rules(path) == ()


# --- Logging -----------------------------------------------------------------------


def test_missing_file_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        load_rules(tmp_path / "does-not-exist.json")
    assert "denying everything" in caplog.text


def test_invalid_file_log_says_where_the_problem_is(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = write_policy(tmp_path, json.dumps({"rules": [rule_json(effect="maybe")]}))
    with caplog.at_level(logging.ERROR):
        load_rules(path)
    assert "rules.0.effect" in caplog.text
