"""`warden limits`: show or change rate limits and approval quotas in the policy file.

warden limits                                  show the limits that apply
warden limits set [--agent ID] [--requests-per-minute N] [--pending N]
warden limits reset [--agent ID]               remove one agent's values, or the defaults
                                               (rejection_window_seconds stays: edit the file)

--policy FILE works before or after set/reset. `set --agent ID` warns if ID isn't in
the agents file (--agents FILE, WARDEN_AGENTS or warden-agents.json).

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

from warden.agents import DEFAULT_AGENTS_PATH, AgentsError, read_agents_file
from warden.check import check_policy
from warden.limits import Limits
from warden.policy import describe_errors, no_duplicate_keys, parse_policy


class LimitsEditError(Exception):
    """The policy file can't be changed; the message says why. Nothing was written."""


def _read(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise LimitsEditError(f"{path} is a symlink; edit the file it points to")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise LimitsEditError(f"can't read {path}: {type(exc).__name__}") from exc
    try:
        parse_policy(raw)  # first: also refuses what json.loads can't parse
        data = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except (ValueError, RecursionError) as exc:  # bad JSON, duplicate keys, not a policy
        raise LimitsEditError(f"{path} is invalid; fix it first (warden check {path})") from exc
    if not isinstance(data, dict):  # pragma: no cover - parse_policy already refused it
        raise LimitsEditError(f"{path} is invalid")
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    try:
        parse_policy(text)
    except ValidationError as exc:
        raise LimitsEditError(f"not changed: {'; '.join(describe_errors(exc, text))}") from exc
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


def _rejection_line(limits: Limits, agent: str) -> str:
    seconds = limits.rejection_window_seconds(agent)
    return f"    rejected actions stay refused for {seconds} seconds" + (
        "" if seconds else " (off): the agent may ask again at once"
    )


def show(path: Path) -> str:
    limits = Limits.model_validate(_read(path).get("limits", {}))
    built_in = (
        limits.default.requests_per_minute is None and limits.default.max_pending_approvals is None
    )
    lines = [
        f"Limits in {path} (restart Warden after changes):",
        f"  default: {limits.requests_per_minute('')} requests/minute, "
        f"{limits.max_pending_approvals('')} pending approvals"
        + ("  (built-in)" if built_in else ""),
        _rejection_line(limits, ""),
    ]
    for agent in sorted(limits.agents):
        lines.append(
            f"  {agent}: {limits.requests_per_minute(agent)} requests/minute, "
            f"{limits.max_pending_approvals(agent)} pending approvals"
        )
        lines.append(_rejection_line(limits, agent))
    return "\n".join(lines)


def change(
    path: Path,
    agent: str | None,
    requests_per_minute: int | None = None,
    pending: int | None = None,
    reset: bool = False,
) -> str:
    """Set (or with reset=True remove) values for `agent`, or the defaults if None.

    A reset keeps rejection_window_seconds: this command can't set it, and removing it
    could quietly shorten how long a human's rejection lasts."""
    if not reset and requests_per_minute is None and pending is None:
        raise LimitsEditError("nothing to set: give --requests-per-minute and/or --pending")
    data = _read(path)
    limits: dict[str, Any] = dict(data.get("limits") or {})
    agents: dict[str, Any] = dict(limits.get("agents") or {})
    entry: dict[str, Any] = dict((agents.get(agent) if agent else limits.get("default")) or {})
    kept = ""
    if reset:
        if agent and agent not in agents:
            raise LimitsEditError(f"no limits for agent {agent!r} in {path}")
        window = entry.get("rejection_window_seconds")
        entry = {} if window is None else {"rejection_window_seconds": window}
        if entry:
            kept = "\nkept rejection_window_seconds (edit the policy file to change it)"
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
    return show(path) + kept


def agent_warning(agent: str, agents_path: Path | None, already_limited: bool) -> str | None:
    """A warning when limits are set for an agent Warden may never see (e.g. a typo).

    With an agents file, agent ids come from tokens: an id that isn't in the file never
    reaches Warden, so its limits do nothing. Without one, ids are self-declared, so
    only a NEW entry gets a reminder to check the spelling. A warning, not a refusal:
    setting limits before `warden agent add` is legitimate and loosens nothing."""
    path = agents_path or Path(os.environ.get("WARDEN_AGENTS") or DEFAULT_AGENTS_PATH)
    try:
        exists = path.exists()
    except OSError as exc:
        return f"warning: can't check agent {agent!r}: can't read {path} ({type(exc).__name__})"
    if not exists:
        if already_limited:
            return None
        return (
            f"warning: no agents file ({path}), so agent ids are self-declared: make sure "
            f"{agent!r} is spelled exactly as the agent sends it"
        )
    try:
        known = {entry.id for entry in read_agents_file(path).agents}
    except AgentsError as exc:
        return f"warning: can't check agent {agent!r} against the agents file: {exc}"
    if agent in known:
        return None
    return (
        f"warning: agent {agent!r} is not in {path}; its limits have no effect until it is "
        f"added (warden agent add {agent})"
    )


def run(args: argparse.Namespace) -> int:
    """`warden limits [set|reset]` from the command line."""
    try:
        if args.action is None:
            print(show(args.policy))
            return 0
        reset = args.action == "reset"
        warning = None
        if not reset and args.agent:
            existing = Limits.model_validate(_read(args.policy).get("limits", {})).agents
            warning = agent_warning(args.agent, args.agents, args.agent in existing)
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
    except OSError as exc:  # e.g. a folder Warden may not write to; nothing was replaced
        print(f"warden: can't use {args.policy}: {type(exc).__name__}", file=sys.stderr)
        return 2
    if warning:
        print(warning, file=sys.stderr)
    return 0
