"""Exact limits of `warden test` files (gaps found by mutation tests)."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from warden.policy_tests import CaseFile, PolicyTestError, load_tests


def case(n: int) -> dict[str, object]:
    return {"name": f"case {n}", "request": {"tool": "t"}, "expect": "deny"}


def write(tmp_path: Path, cases: int, size: int | None = None) -> Path:
    text = json.dumps({"cases": [case(n) for n in range(cases)]})
    if size is not None:
        text += " " * (size - len(text))
    path = tmp_path / "tests.json"
    path.write_text(text)
    return path


def test_file_of_exactly_five_mb_is_read(tmp_path: Path) -> None:
    path = write(tmp_path, 1, size=5 * 1024 * 1024)
    assert path.stat().st_size == 5 * 1024 * 1024
    assert len(load_tests(path).cases) == 1


def test_one_byte_over_five_mb_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PolicyTestError, match="larger than 5 MB"):
        load_tests(write(tmp_path, 1, size=5 * 1024 * 1024 + 1))


def test_exactly_ten_thousand_cases(tmp_path: Path) -> None:
    assert len(load_tests(write(tmp_path, 10_000)).cases) == 10_000
    with pytest.raises(PolicyTestError):
        load_tests(write(tmp_path, 10_001))


def test_loaded_cases_cant_be_changed(tmp_path: Path) -> None:
    tests: CaseFile = load_tests(write(tmp_path, 1))
    with pytest.raises(ValidationError):
        tests.policy = "other.json"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        tests.cases[0].expect = "allow"  # type: ignore[misc,assignment]
    with pytest.raises(ValidationError):
        tests.cases[0].request.tool = "other"  # type: ignore[misc]
