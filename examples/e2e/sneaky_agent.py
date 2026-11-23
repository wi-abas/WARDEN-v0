"""A sneaky agent: tries to get a forbidden call allowed with raw HTTP tricks.

Paths, emails, tool names, URLs, JSON tricks, Host header and token tricks. Most cases
only require "not allow" (the exact reason or status may change as Warden improves).
"""

import json
from typing import Any

from e2e_common import ADMIN_KEY, PORT, Response, check, evaluate, raw, token

ME = token("sneaky-agent")
AUTH: dict[str, str | None] = {"authorization": f"Bearer {ME}"}


def decision(response: Response) -> Any:
    body = response[1]
    return body.get("decision") if isinstance(body, dict) else None


def expect(name: str, response: Response, wanted: str) -> None:
    """wanted: "allow", "require_approval", "deny" (exactly) or "notallow"."""
    got = decision(response)
    ok = got != "allow" if wanted == "notallow" else got == wanted
    reason = response[1].get("reason") if isinstance(response[1], dict) else None
    check(name, ok, f"[{response[0]}] {got} {reason!r}")


def ev(tool: str, arguments: Any, **kwargs: Any) -> Response:
    return evaluate(tool, arguments, ME, **kwargs)


BAD_PATHS = [
    "/workspace/../etc/passwd",
    "/workspace/%2e%2e/etc/passwd",
    "/workspace/%2E%2E%2Fetc",
    "/workspace/..%2fetc",
    "/workspace/./../etc",
    "/workspace//../etc",
    "/workspace/.%2e/etc",
    "/WORKSPACE/a",
    "/workspace\\..\\etc",
    "/workspace/a\x00/../../etc",
    "/workspace/\u2024\u2024/etc",  # one-dot leaders
    "/workspace/\uff0e\uff0e/etc",  # fullwidth dots
    "/work\u200bspace/a",  # zero-width space
    "/workspace\u2215..\u2215etc",  # division slash
    "/workspace/a\u202e",  # right-to-left override
    "\u2215workspace/a",
    "/workspace/~/../etc",
    " /workspace/a",
    "/workspace/a\n/etc",
    "/workspace",
    "/workspace/..",
    "/workspace/a/..",
    # TODO: "/workspace/.. /etc" (dot-dot followed by a space), "/workspace/a/..." and
    # "/workspace/...." are currently allowed; a fix is in progress. Add them here as
    # "notallow" once it is merged.
]

BAD_EMAILS = [
    "x@evil.net",
    "x@example.com.evil.net",
    "x@evil.net,bob@example.com",
    "x@evil.net bob@example.com",
    '"x@evil.net"@example.com',
    "Bob <x@evil.net>@example.com",
    "x%evil.net@example.com",
    "evil.net!x@example.com",
    "x@evil.net\n@example.com",
    "x@evil.net\r\nBcc: y@example.com",
    "x@ex\u0430mple.com",  # Cyrillic a
    "x@example\uff0ecom",
    "x@example.com\u200b",
    "@example.com",
    ".x@example.com",
    "x..y@example.com",
    "x@EXAMPLE.COM.",
    "x@evil.net;bob@example.com",
    "x\\@evil.net@example.com",
    "x@[127.0.0.1]@example.com",
    "<x@evil.net>,bob@example.com",
    "x@evil.net (bob@example.com)",
    "x@evil.net#@example.com",
    "x@sub.example.com",
    "x@evilexample.com",
]

BAD_URLS = [
    "https://api.example.com.evil.net/",
    "https://evil.net/?h=api.example.com",
    "https://api.example.com@evil.net",
    "https://evil.net#@api.example.com",
    "https://api.example.com\\@evil.net",
    "https://API.EXAMPLE.COM.evil.net",
    "https://api\u3002example\u3002com/",  # ideographic full stops
    "https://xn--api-example.com/",
    "//api.example.com",
    "https://[::1]/",
    "https://api.example.com%2eevil.net/",
    # TODO: "javascript://api.example.com/...", "file://api.example.com/etc/passwd" and
    # "https://api.example.com:99999/" are currently allowed by host_in (it checks the
    # host only). Add them once the scheme/port handling is decided and fixed.
]


def main() -> None:
    print("--- paths")
    expect("baseline read allowed", ev("read_file", {"path": "/workspace/a.txt"}), "allow")
    for path in BAD_PATHS:
        expect(f"path {path!r} not allowed", ev("read_file", {"path": path}), "notallow")
    for value in (["/workspace/a", "/etc/passwd"], 1):
        expect(f"path as {type(value).__name__}", ev("read_file", {"path": value}), "notallow")
    expect(
        "path non-ASCII as raw UTF-8",
        ev("read_file", {"path": "/workspace/\u2024\u2024/x"}, ascii_only=False),
        "notallow",
    )

    print("--- emails")
    expect("email BOB@EXAMPLE.COM allowed", ev("send_email", {"to": "BOB@EXAMPLE.COM"}), "allow")
    for to in BAD_EMAILS:
        expect(f"email {to!r} not allowed", ev("send_email", {"to": to}), "notallow")
    odd_to: list[tuple[str, Any]] = [
        ("list", ["bob@example.com", "x@evil.net"]),
        ("object", {"a": "bob@example.com"}),
        ("number", 5),
        ("null", None),
    ]
    for label, to_value in odd_to:
        expect(f"email 'to' as {label}", ev("send_email", {"to": to_value}), "notallow")
    expect(
        "email with extra bcc",
        ev("send_email", {"to": "bob@example.com", "bcc": "x@evil.net"}),
        "notallow",
    )
    expect("email without 'to'", ev("send_email", {"subject": "s"}), "notallow")
    body = json.dumps({"tool": "read_file", "arguments": ["/workspace/a"]}).encode()
    expect("arguments not an object", raw(body, AUTH), "notallow")
    expect("arguments missing", raw(b'{"tool":"read_file"}', AUTH), "notallow")

    print("--- tool names")
    # "fs.read_file" is a real tool, but not with a smuggled "command" argument.
    tools = ["Shell", "shell ", "read_file\u200b", "READ_FILE", "read-file", "shell\x00"]
    for tool in [*tools, "../read_file", "fs.read_file"]:
        response = ev(tool, {"path": "/workspace/a", "command": "ls"})
        expect(f"tool {tool!r} not allowed", response, "notallow")

    print("--- URLs")
    expect(
        "url api.example.com allowed",
        ev("fetch_url", {"url": "https://api.example.com/x"}),
        "allow",
    )
    for url in BAD_URLS:
        expect(f"url {url!r} not allowed", ev("fetch_url", {"url": url}), "notallow")

    print("--- JSON tricks")
    read_json = b'{"tool":"read_file","arguments":{"path":"/workspace/a"'
    tricks = [
        ("duplicate key in arguments", read_json + b',"path":"/etc/passwd"}}'),
        ("duplicate tool key", b'{"tool":"shell",' + read_json[1:] + b"}}"),
        ("duplicate key via \\u escape", read_json + b',"p\\u0061th":"/etc/passwd"}}'),
        ("NaN in arguments", read_json + b',"x":NaN}}'),
        ("trailing garbage", read_json + b'}} {"x":1}'),
        # Only "not allow": the status (200 deny today, 422 after a fix) may change.
        ("lone surrogate in path", read_json + b'\\ud800"}}'),
        ("deep nesting", read_json + b',"x":' + b"[" * 5000 + b"]" * 5000 + b"}}"),
    ]
    for name, data in tricks:
        expect(name, raw(data, AUTH), "notallow")
    # TODO: a body starting with a UTF-8 BOM is currently accepted; a fix is in progress.
    # Add it here as "notallow" once it is merged.
    plain = b'{"tool":"shell","arguments":{"command":"ls"}}'
    for label, content_type in (("text/plain", "text/plain"), ("no", None)):
        response = raw(plain, {**AUTH, "content-type": content_type})
        expect(f"{label} content-type refused", response, "notallow")
    extra_field = ev("read_file", {"path": "/workspace/a"}, extra={"is_admin": True})
    check("extra top-level field refused (422)", extra_field[0] == 422, extra_field[0])
    injected = ev("shell", {"command": "ls"}, extra={"decision": "allow"})
    expect("'decision' injected in the request", injected, "notallow")
    big = {"tool": "read_file", "arguments": {"path": "/workspace/a", "c": "A" * 2_000_000}}
    response = raw(json.dumps(big).encode(), AUTH)
    check("2 MB body refused (413)", response[0] == 413 and decision(response) == "deny")

    print("--- Host and tokens")
    read_a = ("read_file", {"path": "/workspace/a"})
    response = ev(*read_a, headers={"host": "evil.net"})
    check("bad Host header refused (400)", response[0] == 400 and decision(response) == "deny")
    expect(
        "Host localhost:<port> allowed", ev(*read_a, headers={"host": f"localhost:{PORT}"}), "allow"
    )
    response = ev(*read_a, headers={"host": "127.0.0.1.nip.io"})
    check("Host 127.0.0.1.nip.io refused (400)", response[0] == 400)
    response = evaluate(*read_a, None)
    check("no token -> 401", response[0] == 401 and decision(response) == "deny")
    response = evaluate(*read_a, None, extra={"agent_id": "good-agent"})
    check("no token, claims an agent_id -> 401", response[0] == 401)
    response = evaluate(*read_a, "wdn_nope")
    check("garbage token -> 401", response[0] == 401)
    response = ev(*read_a, extra={"agent_id": "good-agent"})
    check("token with another agent's id -> 403", response[0] == 403)
    expect("token with its own agent_id", ev(*read_a, extra={"agent_id": "sneaky-agent"}), "allow")
    response = evaluate(*read_a, None, headers={"authorization": f"Basic {ME}"})
    check("Basic auth scheme -> 401", response[0] == 401)
    expect(
        "lowercase 'bearer' accepted",
        evaluate(*read_a, None, headers={"authorization": f"bearer {ME}"}),
        "allow",
    )
    response = evaluate(*read_a, ADMIN_KEY)
    check("admin key as agent token -> 401", response[0] == 401)
    status = raw(b"", {"x-warden-admin-key": ME}, path="/v1/approvals", method="GET")[0]
    check("agent token as admin key -> 401/403", status in (401, 403), status)
    status = raw(b"", {}, path="/v1/approvals", method="GET")[0]
    check("no admin key on /v1/approvals -> 401/403", status in (401, 403), status)


if __name__ == "__main__":
    main()
