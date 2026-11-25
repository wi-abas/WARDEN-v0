"""Fake servers that can (or pretend to) prove that they are Warden.

Written against the protocol in docs/design/server-identity.md, next to the real server:
tests change one detail at a time and check that the client notices.
"""

import hashlib
import json
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from warden import identity
from warden.api import AnswerSigner


class Proving(BaseHTTPRequestHandler):
    """Answers hello correctly for `secrets`, then calls answer(), which uses reply()."""

    protocol_version = "HTTP/1.1"  # keeps the connection open after the hello
    secrets: tuple[str, ...] = ()
    body = b""
    _key = b""

    def ends(self) -> tuple[str, str]:
        return (
            identity.address(self.connection.getsockname()),
            identity.address(self.connection.getpeername()),
        )

    def _handle(self) -> None:
        self.body = self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.path == identity.HELLO_PATH:
            self.hello()
        else:
            self.answer()

    do_GET = do_POST = _handle  # noqa: N815 (http.server naming)

    def hello(self) -> None:
        asked = json.loads(self.body)
        keys = {identity.key_id(k): k for k in map(identity.proof_key, self.secrets)}
        self._key = keys[asked["key_id"]]
        mac = identity.hello_mac(self._key, asked["nonce"], *self.ends())
        self.raw_reply(200, json.dumps({"mac": mac}).encode(), {})

    def answer(self) -> None:
        raise NotImplementedError

    def mac(self, status: int, body: bytes, headers: dict[str, str], **changed: Any) -> str:
        server, client = self.ends()
        fields: dict[str, Any] = {
            "nonce": self.headers[identity.NONCE_HEADER] or "",
            "server": server,
            "client": client,
            "method": self.command,
            "target": self.path.encode(),
            "request_sha256": hashlib.sha256(self.body).hexdigest(),
            "status": status,
            "retry_after": headers.get("Retry-After", "").encode(),
            "body": body,
            **changed,
        }
        return identity.answer_mac(fields.pop("key", self._key), **fields)

    def reply(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        """A correctly signed answer."""
        headers = headers or {}
        signed = {**headers, identity.MAC_HEADER: self.mac(status, body, headers)}
        self.raw_reply(status, body, signed)

    def raw_reply(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@contextmanager
def serving(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def make_proving(app: FastAPI, secret: str) -> FastAPI:
    """`app`, proving and signing with `secret`'s key (for fake servers built on FastAPI)."""
    key = identity.proof_key(secret)

    @app.post(identity.HELLO_PATH)
    async def hello(request: Request) -> JSONResponse:
        asked = await request.json()
        ends = (identity.address(request.scope[end]) for end in ("server", "client"))
        return JSONResponse({"mac": identity.hello_mac(key, asked["nonce"], *ends)})

    app.add_middleware(AnswerSigner, key_for=lambda scope: key)
    return app


@contextmanager
def raw_impostor(
    act: Callable[[socket.socket], None], host: str = "127.0.0.1", port: int = 0
) -> Iterator[tuple[int, bytearray]]:
    """A raw listening socket. Yields (port, every byte any client sent). `act` is called
    for each connection, with a socket that records what it receives."""
    received = bytearray()

    class Recording(socket.socket):
        def recv(self, *args: Any) -> bytes:
            data = super().recv(*args)
            received.extend(data)
            return data

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen()
    threads: list[threading.Thread] = []

    def one(connection: socket.socket) -> None:
        with Recording(fileno=connection.detach()) as recording:
            recording.settimeout(3)
            try:
                act(recording)
                while recording.recv(65536):  # whatever else the client would send
                    pass
            except OSError:
                pass

    def accept() -> None:
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            thread = threading.Thread(target=one, args=(connection,), daemon=True)
            thread.start()
            threads.append(thread)

    threading.Thread(target=accept, daemon=True).start()
    try:
        yield listener.getsockname()[1], received
    finally:
        try:
            listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        listener.close()
        for thread in list(threads):
            thread.join(timeout=5)


def http_answer(body: bytes, status: str = "200 OK", *headers: str) -> bytes:
    lines = [f"HTTP/1.1 {status}", f"Content-Length: {len(body)}", *headers]
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + body


def read_message(sock: socket.socket) -> bytes:
    """One whole HTTP request or answer (with Content-Length)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.lower().split(b"\r\n"):
        if line.startswith(b"content-length:"):
            length = int(line.split(b":")[1])
    while len(body) < length:
        body += sock.recv(65536)
    return head + b"\r\n\r\n" + body
