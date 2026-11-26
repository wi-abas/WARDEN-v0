"""Server settings: command-line flags, then environment variables, then defaults.

| Setting        | Flag               | Environment variable    | Default               |
|----------------|--------------------|-------------------------|-----------------------|
| Policy file    | --policy           | WARDEN_POLICY           | policies/default.json |
| Port           | --port             | WARDEN_PORT             | 8000                  |
| Audit database | --audit-db         | WARDEN_AUDIT_DB         | warden-audit.db       |
| Retention days | --retention-days   | WARDEN_RETENTION_DAYS   | 90 (0 = keep forever) |
| Admin key      | (none, on purpose) | WARDEN_ADMIN_KEY        | random, printed       |
| Agent tokens   | --agents           | WARDEN_AGENTS           | none (self-declared)  |

The admin key has no flag: command lines are visible to every user on the
machine (`ps`). Environment variables are hidden from OTHER users, but programs
running as the SAME user (including an agent) can usually read them, e.g. via
/proc/<pid>/environ on Linux. Run agents as a different user than Warden.

Any invalid setting stops Warden from starting with a clear message. It never
silently falls back to a default. The host is always 127.0.0.1 (no network
exposure until real authentication exists).
"""

import os
import shlex
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from warden.audit import DEFAULT_AUDIT_PATH, DEFAULT_RETENTION_DAYS, MAX_RETENTION_DAYS
from warden.policy import DEFAULT_POLICY_PATH, replaceable_by_others

DEFAULT_PORT = 8000
MIN_ADMIN_KEY_LENGTH = 32
_POSIX = os.name == "posix"  # Windows has no such permission bits


class SettingsError(ValueError):
    """A setting is invalid. The message says which one and why (never its secret value)."""


@dataclass(frozen=True)
class Settings:
    policy: Path = DEFAULT_POLICY_PATH
    port: int = DEFAULT_PORT
    audit_db: Path = DEFAULT_AUDIT_PATH
    retention_days: int | None = DEFAULT_RETENTION_DAYS  # None = keep forever
    admin_key: str | None = None  # None = generate a random one and print it
    agents: Path | None = None  # None = no agent tokens (agent_id is self-declared)

    def __repr__(self) -> str:  # never show the admin key, e.g. in a traceback
        key = "<set>" if self.admin_key else None
        return (
            f"Settings(policy={self.policy}, port={self.port}, audit_db={self.audit_db}, "
            f"retention_days={self.retention_days}, admin_key={key}, agents={self.agents})"
        )


def unsafe_permissions(path: Path) -> str | None:
    """Why other users could change `path`, or None if they can't (POSIX only).

    The policy decides every answer, so whoever can rewrite it controls Warden: like SSH
    with key files, refuse a policy (or agents file) that other users can write, or that
    is reached through a folder or symlink they could replace.
    """
    if not _POSIX:
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o022:
        return (
            f"{path} can be changed by other users (mode {mode:o}); fix: chmod go-w "
            f"{shlex.quote(str(path))}"
        )
    return replaceable_by_others(path)  # symlinks, and every folder on the way


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError as exc:  # e.g. a folder this user may not enter
        raise SettingsError(f"can't read {path}: {type(exc).__name__}") from exc


def _whole_number(name: str, raw: str) -> int:
    text = raw.strip()
    # Plain 0-9 only (str.isdigit also accepts "²" and Arabic digits), and short enough
    # that int() can't fail or produce absurd values.
    if not (text.isascii() and text.isdigit() and len(text) <= 10):
        raise SettingsError(f"{name} must be a whole number, got {raw[:20]!r}")
    return int(text)


def resolve(
    *,
    policy: str | None = None,
    port: str | None = None,
    audit_db: str | None = None,
    retention_days: str | None = None,
    agents: str | None = None,
    env: Mapping[str, str],
) -> Settings:
    """Combine flags (the keyword arguments) with environment variables."""

    def pick(flag: str | None, var: str) -> tuple[str, str] | None:
        if flag is not None:
            return flag, f"--{var.removeprefix('WARDEN_').lower().replace('_', '-')}"
        if env.get(var):
            return env[var], var
        return None

    values: dict[str, Any] = {}

    if chosen := pick(policy, "WARDEN_POLICY"):
        raw, name = chosen
        path = Path(raw)
        if not _is_file(path):
            raise SettingsError(f"{name}: policy file not found: {raw}")
        values["policy"] = path
    elif not _is_file(DEFAULT_POLICY_PATH):
        raise SettingsError(
            f"no policy file at {DEFAULT_POLICY_PATH}. Create one with `warden init`, "
            "or pass --policy / set WARDEN_POLICY"
        )
    if problem := unsafe_permissions(values.get("policy", DEFAULT_POLICY_PATH)):
        raise SettingsError(f"refusing to use the policy: {problem}")

    if chosen := pick(port, "WARDEN_PORT"):
        raw, name = chosen
        number = _whole_number(name, raw)
        if not 1 <= number <= 65535:
            raise SettingsError(f"{name} must be between 1 and 65535, got {number}")
        values["port"] = number

    if chosen := pick(audit_db, "WARDEN_AUDIT_DB"):
        raw, name = chosen
        path = Path(raw)
        if not path.parent.is_dir():
            raise SettingsError(f"{name}: folder does not exist: {path.parent}")
        values["audit_db"] = path

    audit_path = values.get("audit_db", DEFAULT_AUDIT_PATH)
    if audit_path.is_symlink():
        raise SettingsError(f"audit database {audit_path} is a symlink; refusing to use it")

    if chosen := pick(retention_days, "WARDEN_RETENTION_DAYS"):
        raw, name = chosen
        days = _whole_number(name, raw)
        if days > MAX_RETENTION_DAYS:
            raise SettingsError(
                f"{name} must be between 0 and {MAX_RETENTION_DAYS} (0 = keep forever), got {days}"
            )
        values["retention_days"] = None if days == 0 else days

    if chosen := pick(agents, "WARDEN_AGENTS"):
        raw, name = chosen
        path = Path(raw)
        if not _is_file(path):
            raise SettingsError(
                f"{name}: agents file not found: {raw} (create it with `warden agent add`)"
            )
        if problem := unsafe_permissions(path):
            raise SettingsError(f"refusing to use the agents file: {problem}")
        values["agents"] = path

    key = env.get("WARDEN_ADMIN_KEY")
    if key is not None:
        if len(key) < MIN_ADMIN_KEY_LENGTH:
            raise SettingsError(
                f"WARDEN_ADMIN_KEY must be at least {MIN_ADMIN_KEY_LENGTH} characters "
                f"(it has {len(key)})"
            )
        if key != key.strip() or any(ch.isspace() for ch in key):
            raise SettingsError("WARDEN_ADMIN_KEY must not contain spaces")
        values["admin_key"] = key

    return Settings(**values)
