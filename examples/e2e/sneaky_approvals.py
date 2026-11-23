"""The sneaky agent abuses approvals, admin endpoints and request sizes.

An approval must be bound to the exact action and agent and work once. Admin endpoints
need the right key and Host. Bodies over 64 KiB and odd HTTP framing are refused.
"""

import json
import socket
from typing import Any

from e2e_common import ADMIN_KEY, PORT, Response, admin, check, evaluate, raw, token

ME = token("sneaky-agent")
AUTH: dict[str, str | None] = {"authorization": f"Bearer {ME}"}


def decision(response: Response) -> Any:
    body = response[1]
    return body.get("decision") if isinstance(body, dict) else None


def ev(tool: str, arguments: Any, agent_token: str = ME, **extra: Any) -> Response:
    return evaluate(tool, arguments, agent_token, extra=extra or None)


def status_line(data: bytes) -> bytes:
    """Send raw bytes to Warden; return the first line of the answer."""
    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as sock:
        sock.sendall(data)
        out = b""
        try:
            while chunk := sock.recv(65536):
                out += chunk
        except TimeoutError:
            pass
    return out.split(b"\r\n", 1)[0]


def approvals() -> None:
    print("--- approval replay and modification")
    args = {"path": "/workspace/SNEAKYSECRET-delete-path-42.txt"}
    response = ev("delete_file", args)
    check("delete -> require_approval", decision(response) == "require_approval", response[1])
    aid, action_hash = response[1]["approval_id"], response[1]["action_hash"]
    response = ev("delete_file", args, approval_id=aid)
    check("asking again before a decision: still pending", decision(response) == "require_approval")
    path = f"/v1/approvals/{aid}/approve"
    check(
        "approve with a wrong action_hash -> 409",
        admin("POST", path, {"action_hash": "0" * 64})[0] == 409,
    )
    check(
        "approve with the shown action_hash -> 200",
        admin("POST", path, {"action_hash": action_hash})[0] == 200,
    )
    check("approve twice -> 409", admin("POST", path, {"action_hash": action_hash})[0] == 409)
    response = ev("delete_file", {"path": "/workspace/other.txt"}, approval_id=aid)
    check("approved id on a modified action: not allowed", decision(response) != "allow")
    response = ev("delete_file", args, token("good-agent"), approval_id=aid)
    check("approved id used by another agent: not allowed", decision(response) != "allow")
    response = ev("delete_file", {**args, "force": True}, approval_id=aid)
    check("approved id with an extra argument: not allowed", decision(response) != "allow")
    reordered = dict(reversed(list(args.items())))
    response = ev("delete_file", reordered, approval_id=aid)
    check("approved action runs (key order doesn't matter)", decision(response) == "allow")
    for attempt in ("replay", "replay again"):
        response = ev("delete_file", args, approval_id=aid)
        check(f"approved id {attempt}: not allowed", decision(response) != "allow", response[1])
    response = ev("delete_file", args, approval_id="A" * 32)
    check("unknown approval_id: not allowed", decision(response) != "allow")
    response = ev("read_file", {"path": "/workspace/a"}, approval_id="A" * 32)
    check("unknown approval_id on an allowed call is ignored", decision(response) == "allow")
    response = ev("delete_file", args, approval_id="../../x")
    check("malformed approval_id refused (422)", response[0] == 422)
    response = ev("shell", {"command": "ls"}, approval_id=aid)
    check("approval_id can't unlock a denied tool", decision(response) == "deny")

    print("--- revoke after approve")
    revoke = {"path": "/workspace/revoke-me.txt"}
    response = ev("delete_file", revoke)
    aid2, hash2 = response[1]["approval_id"], response[1]["action_hash"]
    admin("POST", f"/v1/approvals/{aid2}/approve", {"action_hash": hash2})
    # TODO: POST .../deny with an empty JSON body {} currently answers 422; a fix is in
    # progress. Add a check for it here once merged (and keep the revoke below working).
    status = admin("POST", f"/v1/approvals/{aid2}/deny", {"action_hash": hash2})[0]
    check("revoke an approved, unused approval -> 200", status == 200, status)
    response = ev("delete_file", revoke, approval_id=aid2)
    check("revoked approval can't be used", decision(response) == "deny", response[1])

    print("--- hidden characters are shown escaped to the human")
    hidden = {"to": "ann@partner.org", "subject": "pay\u200b", "body": "\u202eevil"}
    response = ev("send_email", hidden)
    check(
        "partner email with hidden characters needs approval",
        decision(response) == "require_approval",
    )
    listed = [
        item
        for item in admin("GET", "/v1/approvals?agent_id=sneaky-agent&tool=send_email")[1]
        if item.get("approval_id") == response[1].get("approval_id")
    ]
    shown = json.dumps(listed[0]["arguments"], ensure_ascii=False) if listed else ""
    check(
        "listed arguments escape hidden characters, with a warning",
        bool(listed)
        and "\u200b" not in shown
        and "\u202e" not in shown
        and bool(listed[0]["warnings"]),
        listed,
    )


def admin_abuse() -> None:
    print("--- admin endpoints")
    body = json.dumps({"ids": ["x" * 32], "action_hashes": ["0" * 64], "approve": True}).encode()
    status = raw(body, {"x-warden-admin-key": "wrong" * 8}, path="/v1/approvals/decide")[0]
    check("group decide with a wrong admin key -> 401/403", status in (401, 403), status)
    status = admin("POST", "/v1/approvals/decide", {"ids": ["x" * 32], "approve": True})[0]
    check("group approve without action_hashes -> 422", status == 422, status)
    headers: dict[str, str | None] = {"x-warden-admin-key": ADMIN_KEY, "host": "evil.net"}
    status = raw(b"", headers, path="/v1/approvals", method="GET")[0]
    check("admin list with a bad Host (DNS rebinding) refused", status >= 400, status)
    status = raw(b"", {"x-warden-admin-key": ADMIN_KEY[:-1]}, path="/v1/approvals", method="GET")[0]
    check("admin key off by one character -> 401/403", status in (401, 403), status)


def sizes() -> None:
    print("--- body sizes and HTTP framing")
    base: dict[str, Any] = {
        "tool": "write_file",
        "arguments": {"path": "/workspace/big", "content": ""},
    }
    room = 64 * 1024 - len(json.dumps(base).encode())
    base["arguments"]["content"] = "A" * room
    response = raw(json.dumps(base).encode(), AUTH)
    check("body of exactly 64 KiB accepted", decision(response) == "allow", response[0])
    base["arguments"]["content"] = "A" * (room + 1)
    response = raw(json.dumps(base).encode(), AUTH)
    check("body of 64 KiB + 1 refused (413)", response[0] == 413 and decision(response) == "deny")
    body = b'{"tool":"read_file","arguments":{"path":"/workspace/a"}}'
    head = f"POST /v1/evaluate HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n".encode()
    head += b"Authorization: Bearer " + ME.encode() + b"\r\ncontent-type: application/json\r\n"
    chunked = head + b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    chunked += f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    framing = {
        "chunked body without a length": chunked,
        "Content-Length smaller than the body": head
        + b"Content-Length: 10\r\nConnection: close\r\n\r\n"
        + body,
        "Content-Length and Transfer-Encoding both": head
        + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        "HTTP/1.0 without a Host header": b"POST /v1/evaluate HTTP/1.0\r\n"
        + b"content-type: application/json\r\nAuthorization: Bearer "
        + ME.encode()
        + f"\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        + body,
    }
    for name, data in framing.items():
        line = status_line(data)
        check(f"{name}: not a 200", line.startswith(b"HTTP/") and b" 200 " not in line, line)


if __name__ == "__main__":
    approvals()
    admin_abuse()
    sizes()
