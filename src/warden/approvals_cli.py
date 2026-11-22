"""`warden approvals`: review and decide pending approvals from the terminal.

warden approvals list [--group]              every pending action, in full
warden approvals list --agent A --tool T     only those (when an agent floods the queue)
warden approvals approve ID [ID ...] [--yes] approve exactly these (all or nothing)
warden approvals reject ID [ID ...] [--yes]  reject exactly these (all or nothing)

Put options before `--` and ids after it if an id starts with "-" (older ids could):
warden approvals approve --yes -- -abc...

Talks to the running server over HTTP (local URLs only, like warden.client). The admin
key comes from the WARDEN_ADMIN_KEY environment variable only: never a flag (flags end
up in shell history and process lists) and never printed.

Before deciding, every named action is fetched again and printed in full, then the
human is asked "Approve these N actions? [y/N]". `--yes` skips the question (scripts).
Everything printed from the server goes through `_text`, so control characters or
look-alike letters can't make the terminal show something other than what is there.

Exit codes: 0 done; 1 refused or failed (or the human said no); 2 usage error, missing
admin key, or the server can't be reached.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, TextIO

from warden.approvals import MAX_GROUP
from warden.client import DEFAULT_URL, ClientConfigError, check_url, open_local
from warden.models import AGENT_ID_PATTERN, APPROVAL_ID_PATTERN, TOOL_NAME_PATTERN

# 100 approvals (the most one decision fetches) of the largest request Warden accepts,
# every character escaped, stay under this.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
TIMEOUT_SECONDS = 10  # mutation-ok: timeout
# One byte more than allowed, to tell "too large" from "exactly the limit".
_READ_LIMIT = MAX_RESPONSE_BYTES + 1  # mutation-ok: reading 2 more changes nothing


class _Unreachable(Exception):
    """No usable answer from the server (exit 2). The message never has the key."""


def _text(value: Any) -> str:
    """Printable ASCII only: strings and JSON with every non-ASCII or control character
    written as an escape (the server already escapes deceptive ones; this is a second,
    independent layer for the terminal)."""
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)[1:-1]
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def _call(url: str, key: str, method: str, path: str, body: Any = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(  # noqa: S310 (check_url: local http only)
        url + path,
        data=data,
        headers={"X-Warden-Admin-Key": key, "content-type": "application/json"},
        method=method,
    )
    try:
        with open_local(request, timeout=TIMEOUT_SECONDS) as response:
            status, raw = response.status, response.read(_READ_LIMIT)
    except urllib.error.HTTPError as error:
        with error:
            status, raw = error.code, error.read(_READ_LIMIT)
    except (urllib.error.URLError, OSError) as exc:
        raise _Unreachable(f"can't reach Warden at {url} ({type(exc).__name__})") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise _Unreachable(
            "answer from Warden too large: narrow the list with --agent and --tool "
            "(approve and reject still work: they fetch only the ids you name)"
        )
    try:
        return status, json.loads(raw)
    except (ValueError, RecursionError):  # not JSON, or nested too deeply to parse
        raise _Unreachable(f"Warden at {url} sent something that isn't JSON") from None


def _print_item(item: Any, number: int, out: TextIO) -> None:
    if not isinstance(item, dict):
        raise _Unreachable("unexpected answer from Warden")
    print(
        f"  [{number}] {_text(item.get('approval_id'))}"
        f"  (expires in {_text(item.get('expires_in_seconds'))}s)",
        file=out,
    )
    print(f"      action_hash: {_text(item.get('action_hash'))}", file=out)
    arguments = json.dumps(item.get("arguments"), ensure_ascii=True, indent=2, sort_keys=True)
    print("      arguments: " + arguments.replace("\n", "\n      "), file=out)
    for warning in item.get("warnings") or []:
        print(f"      WARNING: {_text(warning)}", file=out)


def _print_groups(items: list[Any], out: TextIO) -> None:
    """Items grouped by (agent, tool), in the order given. Every one in full."""
    groups: dict[tuple[str, str], list[Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise _Unreachable("unexpected answer from Warden")
        key = (_text(item.get("agent_id")), _text(item.get("tool")))
        groups.setdefault(key, []).append(item)
    number = 0
    for (agent, tool), members in groups.items():
        print(f"Agent {agent}, tool {tool}: {len(members)} action(s)", file=out)
        for item in members:
            number += 1
            _print_item(item, number, out)


def _pending(
    url: str,
    key: str,
    group: bool,
    ids: list[str] | None = None,
    agent: str | None = None,
    tool: str | None = None,
) -> list[Any]:
    query = {"group": "true"} if group else {}
    if ids:
        query["ids"] = ",".join(ids)  # ids are pattern-checked: no commas inside
    if agent:
        query["agent_id"] = agent
    if tool:
        query["tool"] = tool
    path = "/v1/approvals" + ("?" + urllib.parse.urlencode(query) if query else "")
    status, data = _call(url, key, "GET", path)
    if status == 401:
        raise PermissionError("WARDEN_ADMIN_KEY is wrong (Warden refused it)")
    if status != 200:
        raise _Unreachable(f"Warden answered HTTP {status}")
    if group:
        groups = data.get("groups") if isinstance(data, dict) else None
        if not isinstance(groups, list):
            raise _Unreachable("unexpected answer from Warden")
        return [item for g in groups if isinstance(g, dict) for item in g.get("approvals", [])]
    if not isinstance(data, list):
        raise _Unreachable("unexpected answer from Warden")
    return data


def _confirm(question: str, stdin: TextIO, out: TextIO) -> bool:
    print(f"{question} [y/N] ", end="", file=out, flush=True)  # mutation-ok: flush
    answer = stdin.readline()  # "" at end of input: no
    return answer.strip().lower() in {"y", "yes"}


def run(
    args: argparse.Namespace,
    env: dict[str, str] | None = None,
    stdin: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    env = dict(os.environ) if env is None else env
    stdin, out, err = stdin or sys.stdin, out or sys.stdout, err or sys.stderr
    try:
        url = check_url(args.warden_url or env.get("WARDEN_URL") or DEFAULT_URL)
    except ClientConfigError as exc:
        print(f"warden approvals: {exc}", file=err)
        return 2
    ids: list[str] = args.ids
    if args.action == "list" and ids:
        print("warden approvals: `list` takes no ids", file=err)
        return 2
    agent, tool = getattr(args, "agent", None), getattr(args, "tool", None)
    if args.action != "list" and (agent or tool):
        print("warden approvals: --agent and --tool are for `list`", file=err)
        return 2
    if (agent and not re.fullmatch(AGENT_ID_PATTERN, agent)) or (
        tool and not re.fullmatch(TOOL_NAME_PATTERN, tool)
    ):
        print("warden approvals: that is not an agent id or tool name", file=err)
        return 2
    if args.action != "list":
        problem = (
            "needs at least one approval id"
            if not ids
            else f"takes at most {MAX_GROUP} ids"
            if len(ids) > MAX_GROUP
            else "an id is listed more than once"
            if len(set(ids)) != len(ids)
            else "that is not an approval id"
            if not all(re.fullmatch(APPROVAL_ID_PATTERN, i) for i in ids)
            else None
        )
        if problem:
            print(f"warden approvals {args.action}: {problem}", file=err)
            return 2
    key = env.get("WARDEN_ADMIN_KEY")
    if not key:
        print(
            "warden approvals: set WARDEN_ADMIN_KEY to the admin key Warden printed at "
            "startup (it is never accepted as a flag)",
            file=err,
        )
        return 2
    try:
        if args.action == "list":
            items = _pending(url, key, group=args.group, agent=agent, tool=tool)
            if not items:
                print("No pending approvals.", file=out)
            elif args.group:
                _print_groups(items, out)
            else:
                for number, item in enumerate(items, 1):
                    if isinstance(item, dict):
                        print(
                            f"Agent {_text(item.get('agent_id'))}, tool {_text(item.get('tool'))}",
                            file=out,
                        )
                    _print_item(item, number, out)
            return 0
        return _decide(url, key, ids, args.action == "approve", args.yes, stdin, out, err)
    except PermissionError as exc:
        print(f"warden approvals: {exc}", file=err)
        return 1
    except _Unreachable as exc:
        print(f"warden approvals: {exc}", file=err)
        return 2


def _decide(
    url: str,
    key: str,
    ids: list[str],
    approve: bool,
    yes: bool,
    stdin: TextIO,
    out: TextIO,
    err: TextIO,
) -> int:
    # Show exactly what will be decided: fetched now, every action in full. Only the
    # named ids are fetched, so a flood of other approvals can't block this.
    pending = {
        item.get("approval_id"): item
        for item in _pending(url, key, group=False, ids=ids)  # mutation-ok: same items
        if isinstance(item, dict)
    }
    missing = [i for i in ids if i not in pending]
    if missing:
        for approval_id in missing:
            print(f"not pending (unknown, expired or already decided): {approval_id}", file=err)
        print("warden approvals: nothing changed", file=err)
        return 1
    chosen = [pending[i] for i in ids]
    _print_groups(chosen, out)
    if len({(item.get("agent_id"), item.get("tool")) for item in chosen}) > 1:
        print(
            "warden approvals: a group must be one agent and one tool; decide them "
            "separately. Nothing changed.",
            file=err,
        )
        return 1
    verb = "Approve" if approve else "Reject"
    if not yes and not _confirm(f"{verb} these {len(ids)} actions?", stdin, out):
        print("Nothing changed.", file=out)
        return 1
    # The hashes of what was just shown: Warden refuses the decision if any differs.
    hashes = [item.get("action_hash") for item in chosen]
    body = {"ids": ids, "action_hashes": hashes, "approve": approve}
    status, data = _call(url, key, "POST", "/v1/approvals/decide", body)
    if status == 200 and isinstance(data, dict):
        done = "Approved" if approve else "Rejected"
        print(f"{done} {_text(data.get('count'))} actions.", file=out)
        return 0
    if status == 401:
        raise PermissionError("WARDEN_ADMIN_KEY is wrong (Warden refused it)")
    failed = data.get("failed") if isinstance(data, dict) else None
    if isinstance(failed, list):
        for entry in failed:
            if isinstance(entry, dict):
                print(f"refused: {_text(entry.get('id'))}: {_text(entry.get('reason'))}", file=err)
    error = data.get("error") if isinstance(data, dict) else None
    print(f"warden approvals: {_text(error or f'HTTP {status}, nothing changed')}", file=err)
    return 1
