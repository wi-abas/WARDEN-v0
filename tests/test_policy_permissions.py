"""warden serve refuses a policy file that other users could change."""

import os
import stat
import sys
from pathlib import Path

import pytest
from helpers import BASIC_POLICY

from warden.settings import SettingsError, resolve

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


def policy_in(folder: Path, mode: int) -> Path:
    folder.mkdir(exist_ok=True)
    path = folder / "policy.json"
    path.write_text(BASIC_POLICY.read_text())
    path.chmod(mode)
    return path


@pytest.mark.parametrize("mode", [0o666, 0o646, 0o664, 0o620])
def test_policy_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    path = policy_in(tmp_path / "p", mode)
    with pytest.raises(SettingsError, match="can be changed by other users"):
        resolve(policy=str(path), env={})


@pytest.mark.parametrize("mode", [0o644, 0o600, 0o444])
def test_private_policy_is_accepted(tmp_path: Path, mode: int) -> None:
    path = policy_in(tmp_path / "p", mode)
    assert resolve(policy=str(path), env={}).policy == path


def test_world_writable_folder_without_sticky_bit_is_refused(tmp_path: Path) -> None:
    folder = tmp_path / "shared"
    path = policy_in(folder, 0o644)
    folder.chmod(0o777)
    try:
        with pytest.raises(SettingsError, match="any user can replace files"):
            resolve(policy=str(path), env={})
    finally:
        folder.chmod(0o755)


def test_sticky_world_writable_folder_is_accepted(tmp_path: Path) -> None:
    folder = tmp_path / "sticky"
    path = policy_in(folder, 0o644)
    folder.chmod(0o777 | stat.S_ISVTX)
    try:
        assert resolve(policy=str(path), env={}).policy == path
    finally:
        folder.chmod(0o755)
    assert os.access(path, os.R_OK)
