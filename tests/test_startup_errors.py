"""Startup problems give a clear message and exit code 2, not a traceback."""

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import uvicorn
from helpers import BASIC_POLICY

from warden.api import StartupError, check_port
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


# --- A busy port: say so before printing an admin key that would never work -------------


def test_a_busy_port_stops_before_the_admin_key_and_the_database(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(BASIC_POLICY.read_text())
    policy.chmod(0o644)
    env = {k: v for k, v in os.environ.items() if not k.startswith("WARDEN_")}
    with socket.create_server(("127.0.0.1", 0)) as busy:
        port = busy.getsockname()[1]
        done = subprocess.run(  # noqa: S603 (fixed command)
            [sys.executable, "-c", "from warden.cli import run; run()", "serve"]
            + ["--policy", str(policy), "--port", str(port)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    assert done.returncode == 2
    assert f"warden: can't listen on 127.0.0.1:{port}" in done.stderr
    assert "admin key" not in done.stdout + done.stderr
    assert not (tmp_path / "warden-audit.db").exists()


def test_check_port() -> None:
    with socket.create_server(("127.0.0.1", 0)) as busy:
        port = busy.getsockname()[1]
        with pytest.raises(StartupError, match=f"127.0.0.1:{port}"):
            check_port(port)
    check_port(port)  # free again
    check_port(port)  # and the check itself doesn't keep it


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX SO_REUSEADDR")
def test_check_port_allows_a_quick_restart() -> None:
    """Old connections in TIME_WAIT don't make the port look busy."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port)) as client:
            connection, _ = server.accept()
            connection.close()  # the server side closes first: it gets TIME_WAIT
            assert client.recv(1) == b""
    check_port(port)
