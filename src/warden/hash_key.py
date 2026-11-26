"""The secret key for action hashes (docs/design/keyed-action-hash.md).

The action_hash is stored in the audit log and the approvals table. Keyed with this
secret (HMAC), a copy of the database alone doesn't let anyone guess the arguments by
hashing likely values. The key lives in its own file next to the database
(`<audit-db>.hash-key`), created once with mode 0600 and read on every later start: it
must not change, or stored approvals stop matching (they fail closed).

A broken key file stops Warden from starting. It is never silently replaced: a new key
would quietly orphan every pending approval.
"""

import os
import re
import secrets
import stat
from pathlib import Path

KEY_BYTES = 32
_POSIX = os.name == "posix"


class HashKeyError(ValueError):
    """The key file can't be used. The message never contains the key."""


def key_path_for(database: Path) -> Path:
    """Where the key for `database` lives: next to it, so shared databases share it."""
    return database.with_name(database.name + ".hash-key")


def load_or_create(path: Path) -> bytes:
    """Read the key at `path`, or create a new random one there (mode 0600)."""
    if path.is_symlink():
        raise HashKeyError(f"hash key file {path} is a symlink; refusing to use it")
    text = secrets.token_hex(KEY_BYTES)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return _read(path)  # made earlier (or just now, by another server)
    except OSError as exc:
        raise HashKeyError(f"can't create hash key file {path}: {exc.strerror}") from None
    with os.fdopen(fd, "w") as file:
        file.write(text + "\n")
    return bytes.fromhex(text)


def _read(path: Path) -> bytes:
    try:
        if _POSIX:
            mode = stat.S_IMODE(path.lstat().st_mode)
            if mode & 0o077:
                raise HashKeyError(
                    f"hash key file {path} can be read or changed by other users (mode "
                    f"{mode:o}); fix: chmod 600 {path}"
                )
        text = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise HashKeyError(f"can't read hash key file {path}: {type(exc).__name__}") from None
    if not re.fullmatch(f"[0-9a-f]{{{2 * KEY_BYTES}}}", text):
        raise HashKeyError(
            f"hash key file {path} is damaged (expected {2 * KEY_BYTES} hex characters); "
            "restore it from a backup. Deleting it makes a new key, and approvals "
            "pending now will no longer match"
        )
    return bytes.fromhex(text)
