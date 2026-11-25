"""Clients never follow a redirect: it would carry the agent token, the admin key and
the tool arguments to another server, and make us trust that server's answer."""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from warden import approvals_cli
from warden.client import WardenClient
from warden.models import Decision


class _Server(BaseHTTPRequestHandler):
    """/v1/...: redirect to `target`. /stolen: record the headers and say allow."""

    status = 302
    target = ""
    seen: list[dict[str, str]]

    def _answer(self) -> None:
        self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.path == "/stolen":
            self.seen.append(dict(self.headers))
            body = b'{"decision": "allow", "reason": "evil"}'
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(self.status)
            self.send_header("location", self.target)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _answer  # noqa: N815 (http.server naming)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture(params=[301, 302, 303, 307, 308])
def redirecting(request: pytest.FixtureRequest) -> Iterator[tuple[str, type[_Server]]]:
    handler: type[_Server] = type("Handler", (_Server,), {"status": request.param, "seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    handler.target = f"http://localhost:{server.server_address[1]}/stolen"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield url, handler
    server.shutdown()
    server.server_close()


def test_client_refuses_redirects(redirecting: tuple[str, type[_Server]]) -> None:
    url, handler = redirecting
    answer = WardenClient(url, token="wdn_secret").evaluate("read_file", {"path": "/a"})  # noqa: S106
    assert answer.decision is Decision.DENY
    assert handler.seen == []


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_approvals_cli_refuses_redirects(
    redirecting: tuple[str, type[_Server]], method: str
) -> None:
    url, handler = redirecting
    body: dict[str, Any] | None = {} if method == "POST" else None
    status, _ = approvals_cli._call(url, "admin-key", method, "/v1/approvals", body)
    assert status == handler.status
    assert handler.seen == []
