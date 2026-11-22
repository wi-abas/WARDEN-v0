"""warden init: creates a starter policy, never overwrites."""

from pathlib import Path

import pytest

from warden.check import check_policy
from warden.cli import main, starter_policy
from warden.policy import DEFAULT_POLICY_PATH


def test_init_creates_a_valid_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "policies" / "default.json"
    assert main(["init", str(target)]) == 0
    assert target.read_text() == starter_policy()
    report = check_policy(target)
    assert report.errors == [] and report.warnings == []
    assert "Created" in capsys.readouterr().out


def test_init_never_overwrites(tmp_path: Path) -> None:
    target = tmp_path / "mine.json"
    target.write_text("my precious rules")
    assert main(["init", str(target)]) == 1
    assert target.read_text() == "my precious rules"


def test_init_default_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert (tmp_path / DEFAULT_POLICY_PATH).is_file()


def test_starter_matches_the_repo_default_policy() -> None:
    repo_default = Path(__file__).parent.parent / "policies" / "default.json"
    assert repo_default.read_text() == starter_policy()


def test_missing_policy_error_suggests_init(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["serve"]) == 2
    assert "warden init" in capsys.readouterr().err
