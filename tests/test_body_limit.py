"""The 64 KB body limit holds whatever the headers say (real sockets and plain ASGI)."""

import asyncio
import json
import socket
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from helpers import ADMIN_KEY, BASIC_POLICY, live_server
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from warden.api import MAX_BODY_BYTES, BodySizeLimit, create_app
from warden.audit import SQLiteAuditLog

ALLOWED = json.dumps({"agent_id": "a", "tool": "read_file", "arguments": {}}).encode()
ENDPOINTS = [
    ("POST", "/v1/evaluate"),
    ("POST", "/v1/approvals/decide"),
    ("POST", "/v1/approvals/x/approve"),
    ("POST", "/v1/approvals/x/deny"),
    ("POST", "/v1/approvals/x/lift"),
    ("GET", "/v1/approvals"),
    ("GET", "/health"),
    ("PUT", "/nothing"),
]


@pytest.fixture
def url(tmp_path: Path) -> Iterator[str]:
    log = SQLiteAuditLog(tmp_path / "audit.db")
    with live_server(create_app(BASIC_POLICY, audit_log=log, admin_key=ADMIN_KEY)) as base:
        yield base


def send_raw(url: str, data: bytes) -> tuple[int, bytes]:
    """Send these exact bytes; the status and body of the first answer."""
    parts = urlsplit(url)
    with socket.create_connection((parts.hostname or "", parts.port or 0), timeout=10) as sock:
        sock.sendall(data)
        answer = b""
        while not answer.endswith(b"}"):  # every answer here is a JSON object
            chunk = sock.recv(65536)
            assert chunk, f"closed without an answer: {answer!r}"
            answer += chunk
    head, _, body = answer.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


def chunked(body: bytes) -> bytes:
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)


def head(method: str, path: str, *extra: bytes) -> bytes:
    lines = [
        f"{method} {path} HTTP/1.1".encode(),
        b"Host: 127.0.0.1",
        b"Content-Type: application/json",
        b"X-Warden-Admin-Key: " + ADMIN_KEY.encode(),
        *extra,
    ]
    return b"\r\n".join(lines) + b"\r\n\r\n"


CL, TE = b"Content-Length: 10", b"Transfer-Encoding: chunked"


@pytest.mark.parametrize(
    "headers", [(CL, TE), (TE, CL), (TE,), (CL, b"transfer-ENCODING: Chunked")]
)
@pytest.mark.parametrize("padding", [0, 5 * 1024 * 1024])
def test_transfer_encoding_is_refused(url: str, headers: tuple[bytes, ...], padding: int) -> None:
    # Before the fix: with a small Content-Length too, the 5 MB body got "allow".
    body = chunked(ALLOWED + b" " * padding)
    status, answer = send_raw(url, head("POST", "/v1/evaluate", *headers) + body)
    assert status == 411
    assert json.loads(answer)["decision"] == "deny"


@pytest.mark.parametrize(("method", "path"), ENDPOINTS)
def test_every_endpoint_refuses_transfer_encoding(url: str, method: str, path: str) -> None:
    status, answer = send_raw(url, head(method, path, CL, TE) + chunked(b" " * 100_000))
    assert status == 411
    assert json.loads(answer)["decision"] == "deny"


@pytest.mark.parametrize(("method", "path"), ENDPOINTS)
def test_every_endpoint_refuses_a_large_content_length(url: str, method: str, path: str) -> None:
    size = MAX_BODY_BYTES + 1
    declared = b"Content-Length: %d" % size
    status, answer = send_raw(url, head(method, path, declared) + b" " * size)
    assert status == 413
    assert json.loads(answer)["decision"] == "deny"


def test_an_ordinary_request_still_works(url: str) -> None:
    declared = b"Content-Length: %d" % len(ALLOWED)
    status, answer = send_raw(url, head("POST", "/v1/evaluate", declared) + ALLOWED)
    assert (status, json.loads(answer)["decision"]) == (200, "allow")


# --- Defence in depth: the bytes are counted, whatever the headers promise ------------


def run_limit(
    app: ASGIApp, chunks: list[bytes], headers: list[tuple[bytes, bytes]]
) -> tuple[list[Message], int, list[tuple[int, str]]]:
    """(messages sent, chunks read, rejections) for a body that arrives as `chunks`."""
    sent: list[Message] = []
    reads = 0
    rejected: list[tuple[int, str]] = []

    async def receive() -> Message:
        nonlocal reads
        reads += 1
        return {"type": "http.request", "body": chunks[reads - 1], "more_body": reads < len(chunks)}

    async def send(message: Message) -> None:
        sent.append(message)

    limit = BodySizeLimit(app, on_reject=lambda scope, s, reason: rejected.append((s, reason)))
    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": headers}
    asyncio.run(limit(scope, receive, send))
    return sent, reads, rejected


async def read_everything(scope: Scope, receive: Receive, send: Send) -> None:
    total, more = 0, True
    while more:
        message = await receive()
        total += len(message["body"])
        more = message["more_body"]
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": str(total).encode()})


@pytest.mark.parametrize("headers", [[], [(b"content-length", b"10")]])
def test_the_body_is_cut_off_at_the_limit(headers: list[tuple[bytes, bytes]]) -> None:
    half = b"x" * (MAX_BODY_BYTES // 2)
    sent, reads, rejected = run_limit(read_everything, [half, half, b"x", half, half], headers)
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["decision"] == "deny"
    assert reads == 3  # stopped at the byte over the limit: the rest is never read
    assert rejected == [(413, "request too large")]


def test_exactly_the_limit_gets_through() -> None:
    half = b"x" * (MAX_BODY_BYTES // 2)
    sent, _, rejected = run_limit(read_everything, [half, half], [])
    assert sent[0]["status"] == 200 and sent[1]["body"] == str(MAX_BODY_BYTES).encode()
    assert rejected == []
