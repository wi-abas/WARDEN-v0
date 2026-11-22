"""`warden limits`: show or change rate limits and approval quotas in the policy file.

warden limits                                  show the limits that apply
warden limits set [--agent ID] [--requests-per-minute N] [--pending N]
warden limits reset [--agent ID]               remove one agent's values, or the defaults

Edits only the "limits" section. The new file must pass the same checks as
`warden check` (no errors) before it replaces the old one, atomically and with the
same permissions, so a mistake never leaves a half-written or broken policy behind.
JSON has no comments; the file is rewritten with 2-space indentation.
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from warden.check import check_policy
from warden.limits import Limits
from warden.policy import DuplicateKeyError, describe_errors, no_duplicate_keys, parse_policy


class LimitsEditError(Exception):
    """The policy file can't be changed; the message says why. Nothing was written."""


def _read(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise LimitsEditError(f"{path} is a symlink; edit the file it points to")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LimitsEditError(f"can't read {path}: {type(exc).__name__}") from exc
    try:
        data = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        parse_policy(raw)
    except (json.JSONDecodeError, RecursionError, DuplicateKeyError, ValidationError) as exc:
        raise LimitsEditError(f"{path} is invalid; fix it first (warden check {path})") from exc
    if not isinstance(data, dict):  # pragma: no cover - parse_policy already refused it
        raise LimitsEditError(f"{path} is invalid")
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    try:
        parse_policy(text)
    except ValidationError as exc:
        raise LimitsEditError(f"not changed: {'; '.join(describe_errors(exc))}") from exc
    mode = path.stat().st_mode & 0o777
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        tmp.chmod(mode)
        report = check_policy(tmp)
        if report.errors:  # pragma: no cover - parse_policy above catches the same
            raise LimitsEditError("; ".join(report.errors))
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def show(path: Path) -> str:
    limits = Limits.model_validate(_read(path).get("limits", {}))
    lines = [
        f"Limits in {path} (restart Warden after changes):",
        f"  default: {limits.requests_per_minute('')} requests/minute, "
        f"{limits.max_pending_approvals('')} pending approvals"
        + ("" if limits.default.model_fields_set else "  (built-in)"),
    ]
    for agent in sorted(limits.agents):
        lines.append(
            f"  {agent}: {limits.requests_per_minute(agent)} requests/minute, "
            f"{limits.max_pending_approvals(agent)} pending approvals"
        )
    return "\n".join(lines)


def change(
    path: Path,
    agent: str | None,
    requests_per_minute: int | None = None,
    pending: int | None = None,
    reset: bool = False,
) -> str:
    """Set (or with reset=True remove) values for `agent`, or the defaults if None."""
    if not reset and requests_per_minute is None and pending is None:
        raise LimitsEditError("nothing to set: give --requests-per-minute and/or --pending")
    data = _read(path)
    limits: dict[str, Any] = dict(data.get("limits") or {})
    agents: dict[str, Any] = dict(limits.get("agents") or {})
    entry: dict[str, Any] = dict((agents.get(agent) if agent else limits.get("default")) or {})
    if reset:
        if agent and agent not in agents:
            raise LimitsEditError(f"no limits for agent {agent!r} in {path}")
        entry = {}
    if requests_per_minute is not None:
        entry["requests_per_minute"] = requests_per_minute
    if pending is not None:
        entry["max_pending_approvals"] = pending
    if agent:
        if entry:
            agents[agent] = entry
        else:
            agents.pop(agent, None)
        limits["agents"] = agents
    else:
        limits["default"] = entry
    data["limits"] = {k: v for k, v in limits.items() if v}
    if not data["limits"]:
        del data["limits"]
    _write(path, data)
    return show(path)


def run(args: argparse.Namespace) -> int:
    """`warden limits [set|reset]` from the command line."""
    try:
        if args.action is None:
            print(show(args.policy))
            return 0
        reset = args.action == "reset"
        print(
            change(
                args.policy,
                args.agent,
                requests_per_minute=None if reset else args.requests_per_minute,
                pending=None if reset else args.pending,
                reset=reset,
            )
        )
    except LimitsEditError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    return 0
