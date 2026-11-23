"""Shared helpers for the end-to-end scenario (run by run_all.sh, not on their own).

run_all.sh starts a real Warden server and sets these environment variables:
  E2E_STATE         temp folder holding the agent tokens (token-<agent>)
  E2E_PORT          the port Warden listens on
  WARDEN_ADMIN_KEY  the admin key (plays the human approving actions)

Every check prints one line, "PASS  name" or "FAIL  name"; run_all.sh counts them.
A script that crashes is counted as a failure by run_all.sh.

Also a tiny command for run_all.sh: `python e2e_common.py pending AGENT [TOOL]` prints the
ids of that agent's pending approvals.
"""

import http.client
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

STATE = Path(os.environ.get("E2E_STATE", "."))
PORT = int(os.environ.get("E2E_PORT", "0"))
URL = f"http://127.0.0.1:{PORT}"
ADMIN_KEY = os.environ.get("WARDEN_ADMIN_KEY", "")

Response = tuple[int, Any, dict[str, str]]


def token(agent: str) -> str:
    return (STATE / f"token-{agent}").read_text().strip()


def check(name: str, ok: bool, detail: object = "") -> bool:
    """Print one PASS/FAIL line. `detail` helps debugging (never real secrets here)."""
    line = f"{'PASS' if ok else 'FAIL'}  {name}"
    if detail != "":
        line += f"  -> {str(detail)[:200]}"
    print(line, flush=True)
    return ok


def raw(
    body: bytes,
    headers: dict[str, str | None] | None = None,
    path: str = "/v1/evaluate",
    method: str = "POST",
) -> Response:
    """Send exactly these bytes. A header set to None is not sent at all."""
    wanted: dict[str, str | None] = {"content-type": "application/json"}
    wanted.update(headers or {})
    sent = {k: v for k, v in wanted.items() if v is not None}
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    try:
        has_host = "host" in {k.lower() for k in sent}
        connection.putrequest(method, path, skip_host=has_host, skip_accept_encoding=True)
        for key, value in sent.items():
            connection.putheader(key, value)
        connection.putheader("content-length", str(len(body)))
        connection.endheaders()
        connection.send(body)
        response = connection.getresponse()
        data = response.read()
        status, response_headers = response.status, dict(response.getheaders())
    finally:
        connection.close()
    try:
        parsed: Any = json.loads(data)
    except ValueError:
        parsed = {"_raw": data[:200].decode(errors="replace")}
    return status, parsed, {k.lower(): v for k, v in response_headers.items()}


def evaluate(
    tool: str,
    arguments: Any,
    agent_token: str | None,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str | None] | None = None,
    ascii_only: bool = True,
) -> Response:
    """POST /v1/evaluate as an agent (Bearer token), with optional extra body fields."""
    body: dict[str, Any] = {"tool": tool, "arguments": arguments}
    body.update(extra or {})
    sent: dict[str, str | None] = {}
    if agent_token is not None:
        sent["authorization"] = f"Bearer {agent_token}"
    sent.update(headers or {})
    return raw(json.dumps(body, ensure_ascii=ascii_only).encode(), sent)


def admin(method: str, path: str, body: Any = None) -> Response:
    """Call an admin endpoint with the admin key."""
    data = b"" if body is None else json.dumps(body).encode()
    return raw(data, {"x-warden-admin-key": ADMIN_KEY}, path=path, method=method)


def pending(agent: str, tool: str | None = None) -> list[dict[str, Any]]:
    query = {"agent_id": agent, **({"tool": tool} if tool else {})}
    status, items, _ = admin("GET", "/v1/approvals?" + urllib.parse.urlencode(query))
    return items if status == 200 and isinstance(items, list) else []


def wait_for_pending(
    agent: str, tool: str, match: dict[str, Any], timeout: float = 10.0
) -> dict[str, Any] | None:
    """The pending approval whose arguments include `match`, once it shows up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for item in pending(agent, tool):
            arguments = item.get("arguments") or {}
            if all(arguments.get(k) == v for k, v in match.items()):
                return item
        time.sleep(0.1)
    return None


def decide(item: dict[str, Any] | None, approve: bool) -> int:
    """Approve or deny one listed approval, with the action_hash the human was shown."""
    if item is None:
        return 0
    verb = "approve" if approve else "deny"
    path = f"/v1/approvals/{item['approval_id']}/{verb}"
    status, _, _ = admin("POST", path, {"action_hash": item["action_hash"]})
    return status


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "pending":
        tool = sys.argv[3] if len(sys.argv) == 4 else None
        print(" ".join(item["approval_id"] for item in pending(sys.argv[2], tool)))
    else:
        sys.exit("usage: e2e_common.py pending AGENT [TOOL]")
