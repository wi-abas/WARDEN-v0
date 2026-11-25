"""warden serve refuses a policy file that other users could change."""

import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest
from helpers import BASIC_POLICY

from warden.policy import replaceable_by_others
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


# --- Symlinks and the folders on the way --------------------------------------------------


def accepted(path: Path) -> bool:
    try:
        resolve(policy=str(path), env={})
    except SettingsError as exc:
        assert "refusing to use the policy" in str(exc)
        return False
    return True


def test_symlink_in_a_world_writable_folder_is_refused(tmp_path: Path) -> None:
    # Anyone could point the link at their own policy.
    real = policy_in(tmp_path / "private", 0o600)
    shared = tmp_path / "shared"
    shared.mkdir()
    link = shared / "policy.json"
    link.symlink_to(real)
    shared.chmod(0o777)
    try:
        with pytest.raises(SettingsError, match="any user can replace files"):
            resolve(policy=str(link), env={})
    finally:
        shared.chmod(0o755)
    assert accepted(link)


def test_symlink_chain_through_a_world_writable_folder_is_refused(tmp_path: Path) -> None:
    real = policy_in(tmp_path / "private", 0o600)
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "middle").symlink_to(real)
    link = tmp_path / "link.json"
    link.symlink_to("shared/../shared/./middle")  # relative target
    assert accepted(link)
    shared.chmod(0o777)
    try:
        assert not accepted(link)
    finally:
        shared.chmod(0o755)


def test_linked_folder_in_a_world_writable_folder_is_refused(tmp_path: Path) -> None:
    policy_in(tmp_path / "private", 0o600)
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "conf").symlink_to(tmp_path / "private")
    path = shared / "conf" / "policy.json"
    assert accepted(path)
    shared.chmod(0o777)
    try:
        assert not accepted(path)
    finally:
        shared.chmod(0o755)


def test_world_writable_grandparent_is_refused(tmp_path: Path) -> None:
    # The private folder itself could be renamed away and replaced.
    shared = tmp_path / "shared"
    shared.mkdir()
    path = policy_in(shared / "private", 0o600)
    shared.chmod(0o777)
    try:
        assert not accepted(path)
    finally:
        shared.chmod(0o755)


def test_target_writable_by_others_is_refused_through_a_symlink(tmp_path: Path) -> None:
    link = tmp_path / "link.json"
    link.symlink_to(policy_in(tmp_path / "p", 0o666))
    assert not accepted(link)


def test_relative_policy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_in(tmp_path / "p", 0o600)
    monkeypatch.chdir(tmp_path)
    assert accepted(Path("p/../p/policy.json"))


@pytest.mark.parametrize("through_link", [False, True])
def test_sticky_folder_entry_of_another_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, through_link: bool
) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    path = sticky / "policy.json"
    if through_link:
        path.symlink_to(policy_in(tmp_path / "p", 0o600))
    else:
        policy_in(sticky, 0o644)
    sticky.chmod(0o1777)
    try:
        assert accepted(path)  # ours
        monkeypatch.setattr(os, "geteuid", lambda: 987654)
        with pytest.raises(SettingsError, match="owned by another user"):
            resolve(policy=str(path), env={})
    finally:
        sticky.chmod(0o755)


def test_ordinary_tmp_paths_work() -> None:
    # On macOS /tmp is a symlink to /private/tmp (owned by root, so nobody can change it).
    with tempfile.TemporaryDirectory(dir="/tmp") as folder:  # noqa: S108
        assert accepted(policy_in(Path(folder), 0o600))


def test_symlink_loop_and_unreadable_folder_are_clear_errors(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    with pytest.raises(SettingsError, match="not found"):
        resolve(policy=str(loop), env={})
    assert "can't be checked" in (replaceable_by_others(loop) or "")
    assert "can't be checked" in (replaceable_by_others(tmp_path / "missing") or "")


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads all")
def test_policy_in_a_locked_folder_is_a_clear_error(tmp_path: Path) -> None:
    path = policy_in(tmp_path / "p", 0o600)
    (tmp_path / "p").chmod(0)
    try:
        with pytest.raises(SettingsError, match="can't read"):
            resolve(policy=str(path), env={})
        with pytest.raises(SettingsError, match="can't read"):
            resolve(policy=str(path), agents=str(path), env={})
    finally:
        (tmp_path / "p").chmod(0o755)


# --- Group-writable folders ---------------------------------------------------------------


@pytest.mark.parametrize("mode", [0o775, 0o770, 0o2775])
@pytest.mark.parametrize("depth", ["folder", "grandparent"])
def test_group_writable_folder_on_the_way_is_refused(tmp_path: Path, mode: int, depth: str) -> None:
    shared = tmp_path / "shared folder"
    shared.mkdir()
    path = policy_in(shared if depth == "folder" else shared / "private", 0o600)
    agents = path.with_name("agents.json")
    agents.write_text('{"agents": []}')
    agents.chmod(0o600)
    safe = policy_in(tmp_path / "safe", 0o600)
    assert accepted(path)
    shared.chmod(mode)
    try:
        with pytest.raises(SettingsError, match="members of its group can replace") as caught:
            resolve(policy=str(path), env={})
        assert f"chmod go-w '{shared}'" in str(caught.value)  # exact folder, quoted
        with pytest.raises(SettingsError, match="refusing to use the agents file"):
            resolve(policy=str(safe), agents=str(agents), env={})
    finally:
        shared.chmod(0o755)


def test_symlink_in_a_group_writable_folder_is_refused(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    link = shared / "policy.json"
    link.symlink_to(policy_in(tmp_path / "private", 0o600))
    assert accepted(link)
    shared.chmod(0o775)
    try:
        assert not accepted(link)
    finally:
        shared.chmod(0o755)


def test_sticky_group_writable_folder_is_accepted(tmp_path: Path) -> None:
    folder = tmp_path / "sticky"
    path = policy_in(folder, 0o644)
    folder.chmod(0o1775)
    try:
        assert accepted(path)
    finally:
        folder.chmod(0o755)


def test_permissions_are_not_checked_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = policy_in(tmp_path / "p", 0o666)
    monkeypatch.setattr("warden.settings._POSIX", False)
    assert accepted(path)


# --- Files, folders and symlinks owned by someone else ------------------------------------


OTHER = 987654


def set_owner(monkeypatch: pytest.MonkeyPatch, target: Path, uid: int, mode: int = 0) -> None:
    """Pretend `target` belongs to `uid`, plus extra mode bits (chown needs root)."""
    real_stat = Path.stat

    def fake_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        info = real_stat(self, follow_symlinks=follow_symlinks)
        if self != target:
            return info
        fields = list(info)
        fields[0] = info.st_mode | mode
        fields[4] = uid
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "lstat", lambda self: self.stat(follow_symlinks=False))


@pytest.mark.parametrize("kind", ["policy", "agents"])
@pytest.mark.parametrize("which", ["file", "folder", "grandparent", "link", "root"])
def test_anything_owned_by_another_user_on_the_way_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, which: str
) -> None:
    (tmp_path / "top").mkdir()
    real = policy_in(tmp_path / "top" / "conf", 0o600)
    safe = policy_in(tmp_path / "safe", 0o600)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    places = {
        "file": real,
        "folder": real.parent,
        "grandparent": real.parent.parent,
        "link": link,
        "root": Path("/"),
    }
    assert accepted(link)
    set_owner(monkeypatch, places[which], OTHER)
    with pytest.raises(SettingsError, match="owned by another user") as caught:
        if kind == "policy":
            resolve(policy=str(link), env={})
        else:
            # ("/" owned by someone else already stops the policy.)
            resolve(policy=str(safe), agents=str(link), env={})
    message = str(caught.value)
    assert f"{places[which]}, owned by another user (uid {OTHER})" in message
    assert f"sudo chown -h {os.geteuid()} {places[which]}" in message


@pytest.mark.parametrize("which", ["file", "folder", "link"])
def test_root_owned_entries_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    real = policy_in(tmp_path / "conf", 0o644)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    set_owner(monkeypatch, {"file": real, "folder": real.parent, "link": link}[which], 0)
    assert accepted(link)


def test_root_owned_group_writable_folder_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # e.g. macOS /Applications (root:admin 775)
    path = policy_in(tmp_path / "apps", 0o644)
    set_owner(monkeypatch, path.parent, 0, mode=0o020)
    prefix = "" if os.geteuid() == 0 else "sudo "
    with pytest.raises(SettingsError, match=f"or {prefix}chmod go-w {path.parent}"):
        resolve(policy=str(path), env={})


@pytest.mark.parametrize("folder_mode", [0o1777, 0o1775])
def test_sticky_folder_refuses_just_the_other_users_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, folder_mode: int
) -> None:
    folder = tmp_path / "sticky"
    path = policy_in(folder, 0o644)
    folder.chmod(folder_mode)
    try:
        assert accepted(path)
        set_owner(monkeypatch, path, OTHER)
        with pytest.raises(SettingsError, match="policy.json, owned by another user"):
            resolve(policy=str(path), env={})
    finally:
        folder.chmod(0o755)
