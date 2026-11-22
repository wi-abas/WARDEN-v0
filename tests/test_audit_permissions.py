"""The audit database is private to the user running Warden."""

import os
import stat
import sys
from pathlib import Path

import pytest

from warden.audit import SQLiteAuditLog

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_new_database_is_private(tmp_path: Path) -> None:
    SQLiteAuditLog(tmp_path / "a.db")
    assert mode(tmp_path / "a.db") == 0o600


def test_existing_open_database_is_tightened(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "a.db"
    SQLiteAuditLog(path)
    path.chmod(0o644)
    SQLiteAuditLog(path)
    assert mode(path) == 0o600
    assert "restricted it to you" in caplog.text


def test_private_database_left_alone(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "a.db"
    SQLiteAuditLog(path)
    SQLiteAuditLog(path)
    assert mode(path) == 0o600
    assert "restricted" not in caplog.text


@pytest.mark.parametrize("dangling", [True, False])
def test_symlinked_database_is_refused(tmp_path: Path, dangling: bool) -> None:
    target = tmp_path / "elsewhere.db"
    if not dangling:
        target.write_bytes(b"")
    link = tmp_path / "audit.db"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        SQLiteAuditLog(link)
    assert target.read_bytes() == b"" if not dangling else not target.exists()
