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


def test_init_creates_a_policy_serve_accepts_even_with_a_loose_umask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from warden.settings import resolve

    old = os.umask(0o002)  # common on Linux: new files are group-writable
    try:
        target = tmp_path / "p.json"
        assert main(["init", str(target)]) == 0
    finally:
        os.umask(old)
    assert resolve(policy=str(target), env={}).policy == target


def test_init_next_steps_work_without_uv(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "p.json"
    assert main(["init", str(target)]) == 0
    out = capsys.readouterr().out
    assert f"  2. warden check {target}\n" in out
    assert "  3. warden serve" in out
    assert "put `uv run` in front" in out  # only a hint, for uv projects


def test_init_names_the_policy_to_serve_unless_it_is_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert "  3. warden serve\n" in capsys.readouterr().out
    assert main(["init", "mine.json"]) == 0
    assert "  3. warden serve --policy mine.json\n" in capsys.readouterr().out
