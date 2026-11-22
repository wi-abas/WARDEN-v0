"""Duplicate keys in a policy file are an error, never silently resolved."""

import logging
from pathlib import Path

import pytest

from warden.check import check_policy
from warden.policy import load_policy

CASES = [
    '{"rules":[{"id":"r","tool":"t","effect":"allow","effect":"deny"}]}',
    '{"rules":[],"rules":[{"id":"r","tool":"t","effect":"allow"}]}',
    '{"tools":{"t":{"arguments":["a"]},"t":{"arguments":[]}},"rules":[]}',
    '{"rules":[{"id":"r","tool":"t","effect":"deny","when":[{"arg":"a","arg":"b","op":"exists"}]}]}',
]


@pytest.mark.parametrize("raw", CASES)
def test_duplicate_key_loads_nothing(
    raw: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "p.json"
    path.write_text(raw)
    with caplog.at_level(logging.ERROR):
        assert load_policy(path).rules == ()
    assert "duplicate key" in caplog.text


@pytest.mark.parametrize("raw", CASES)
def test_warden_check_reports_duplicate_keys(raw: str, tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_text(raw)
    [error] = check_policy(path).errors
    assert error.startswith("duplicate key")


def test_same_key_in_different_objects_is_fine(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_text(
        '{"rules":[{"id":"a","tool":"t","effect":"allow"},{"id":"b","tool":"u","effect":"deny"}]}'
    )
    assert len(load_policy(path).rules) == 2


def test_broken_json_still_reported_by_location(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_text('{"rules": [')
    assert check_policy(path).errors and "duplicate" not in check_policy(path).errors[0]
