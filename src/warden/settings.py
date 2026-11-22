"""Server settings: command-line flags, then environment variables, then defaults.

| Setting        | Flag               | Environment variable    | Default               |
|----------------|--------------------|-------------------------|-----------------------|
| Policy file    | --policy           | WARDEN_POLICY           | policies/default.json |
| Port           | --port             | WARDEN_PORT             | 8000                  |
| Audit database | --audit-db         | WARDEN_AUDIT_DB         | warden-audit.db       |
| Retention days | --retention-days   | WARDEN_RETENTION_DAYS   | 90 (0 = keep forever) |
| Admin key      | (none, on purpose) | WARDEN_ADMIN_KEY        | random, printed       |

The admin key has no flag: command lines are visible to every program on the
machine (`ps`), environment variables are not.

Any invalid setting stops Warden from starting with a clear message. It never
silently falls back to a default. The host is always 127.0.0.1 (no network
exposure until real authentication exists).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from warden.audit import DEFAULT_AUDIT_PATH, DEFAULT_RETENTION_DAYS
from warden.policy import DEFAULT_POLICY_PATH

DEFAULT_PORT = 8000
MIN_ADMIN_KEY_LENGTH = 32


class SettingsError(ValueError):
    """A setting is invalid. The message says which one and why (never its secret value)."""


@dataclass(frozen=True)
class Settings:
    policy: Path = DEFAULT_POLICY_PATH
    port: int = DEFAULT_PORT
    audit_db: Path = DEFAULT_AUDIT_PATH
    retention_days: int | None = DEFAULT_RETENTION_DAYS  # None = keep forever
    admin_key: str | None = None  # None = generate a random one and print it

    def __repr__(self) -> str:  # never show the admin key, e.g. in a traceback
        key = "<set>" if self.admin_key else None
        return (
            f"Settings(policy={self.policy}, port={self.port}, audit_db={self.audit_db}, "
            f"retention_days={self.retention_days}, admin_key={key})"
        )


def _whole_number(name: str, raw: str) -> int:
    if not raw.strip().isdigit():
        raise SettingsError(f"{name} must be a whole number, got {raw!r}")
    return int(raw)


def resolve(
    *,
    policy: str | None = None,
    port: str | None = None,
    audit_db: str | None = None,
    retention_days: str | None = None,
    env: Mapping[str, str],
) -> Settings:
    """Combine flags (the keyword arguments) with environment variables."""

    def pick(flag: str | None, var: str) -> tuple[str, str] | None:
        if flag is not None:
            return flag, f"--{var.removeprefix('WARDEN_').lower().replace('_', '-')}"
        if env.get(var):
            return env[var], var
        return None

    values: dict = {}

    if chosen := pick(policy, "WARDEN_POLICY"):
        raw, name = chosen
        path = Path(raw)
        if not path.is_file():
            raise SettingsError(f"{name}: policy file not found: {raw}")
        values["policy"] = path
    elif not DEFAULT_POLICY_PATH.is_file():
        raise SettingsError(
            f"no policy file at {DEFAULT_POLICY_PATH}; pass --policy or set WARDEN_POLICY"
        )

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

    if chosen := pick(retention_days, "WARDEN_RETENTION_DAYS"):
        raw, name = chosen
        days = _whole_number(name, raw)
        values["retention_days"] = None if days == 0 else days

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
