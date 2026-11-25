"""Startup problems give a clear message and exit code 2, not a traceback."""

import sys
from pathlib import Path

import pytest
import uvicorn
from helpers import BASIC_POLICY

from warden.cli import main


def serve(tmp_path: Path, audit_db: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server started"))
    policy = tmp_path / "policy.json"
    policy.write_text(BASIC_POLICY.read_text())
    policy.chmod(0o644)
    return main(["serve", "--policy", str(policy), "--audit-db", str(audit_db)])


def test_corrupted_audit_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "audit.db"
    bad.write_bytes(b"this is not a database" * 100)
    bad.chmod(0o600)
    assert serve(tmp_path, bad, monkeypatch) == 2
    err = capsys.readouterr().err
    assert "can't open the audit database" in err and "Traceback" not in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_unwritable_audit_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "ro"
    folder.mkdir()
    folder.chmod(0o500)
    try:
        assert serve(tmp_path, folder / "audit.db", monkeypatch) == 2
    finally:
        folder.chmod(0o700)
    assert "can't open the audit database" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
@pytest.mark.parametrize("flag", ["--policy", "--audit-db", "--agents"])
def test_setting_in_a_closed_folder(
    tmp_path: Path, flag: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("server started"))
    policy = tmp_path / "policy.json"
    policy.write_text(BASIC_POLICY.read_text())
    policy.chmod(0o644)
    closed = tmp_path / "closed"
    closed.mkdir(mode=0o000)
    try:
        # The last --policy wins; the valid one is for the other flags.
        assert main(["serve", "--policy", str(policy), flag, str(closed / "x")]) == 2
    finally:
        closed.chmod(0o700)
    assert capsys.readouterr().err.startswith("warden: ")
