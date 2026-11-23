"""Warden restarts while an approval is pending (P) and one is approved but unused (A).

Usage: python restart.py before|after (run_all.sh restarts Warden in between).
After the restart: P can't be approved until the agent asks again (Warden never stores
arguments, so the human would approve blind), P's id can't be used for another action,
and P and A each work exactly once.
"""

import json
import sys
from typing import Any

from e2e_common import STATE, admin, check, evaluate, token

AGENT = token("good-agent")
SAVED = STATE / "restart-state.json"
P = {"path": "/workspace/RESTARTSECRET-pending.txt"}
A = {"path": "/workspace/RESTARTSECRET-approved.txt"}


def use(arguments: dict[str, Any], approval_id: str) -> tuple[Any, Any]:
    body = evaluate("delete_file", arguments, AGENT, extra={"approval_id": approval_id})[1]
    return body.get("decision"), body.get("reason")


def before() -> None:
    _, p, _ = evaluate("delete_file", P, AGENT)
    _, a, _ = evaluate("delete_file", A, AGENT)
    approve = f"/v1/approvals/{a['approval_id']}/approve"
    status = admin("POST", approve, {"action_hash": a["action_hash"]})[0]
    check("restart: A approved before the restart", status == 200, status)
    ids = {"P": [p["approval_id"], p["action_hash"]], "A": [a["approval_id"]]}
    SAVED.write_text(json.dumps(ids))  # ids and hashes only, never arguments


def after() -> None:
    saved = json.loads(SAVED.read_text())
    p_id, p_hash = saved["P"]
    (a_id,) = saved["A"]
    listed = [x for x in admin("GET", "/v1/approvals")[1] if x["approval_id"] == p_id]
    check(
        "restart: P still listed, without arguments",
        len(listed) == 1 and listed[0]["arguments"] is None,
        listed,
    )
    status, body, _ = admin("POST", f"/v1/approvals/{p_id}/approve", {"action_hash": p_hash})
    check("restart: P can't be approved blind (409)", status == 409, body)
    group = {"ids": [p_id], "action_hashes": [p_hash], "approve": True}
    status, body, _ = admin("POST", "/v1/approvals/decide", group)
    check("restart: P can't be group-approved blind (409)", status == 409, body)
    got = use({"path": "/workspace/different.txt"}, p_id)
    check("restart: P's id can't be used for another action", got[0] == "deny", got)
    got = use(P, p_id)
    check("restart: agent asks again -> still pending", got[0] == "require_approval", got)
    listed = [x for x in admin("GET", "/v1/approvals")[1] if x["approval_id"] == p_id]
    check("restart: P now shows its arguments", bool(listed) and listed[0]["arguments"] == P)
    status, body, _ = admin("POST", f"/v1/approvals/{p_id}/approve", {"action_hash": p_hash})
    check("restart: P can be approved now", status == 200, body)
    check("restart: P works once", use(P, p_id)[0] == "allow")
    check("restart: P doesn't work twice", use(P, p_id)[0] == "deny")
    check("restart: A (approved before restart) works once", use(A, a_id)[0] == "allow")
    check("restart: A doesn't work twice", use(A, a_id)[0] == "deny")


if __name__ == "__main__":
    {"before": before, "after": after}[sys.argv[1]]()
