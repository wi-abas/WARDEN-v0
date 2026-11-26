"""`warden approvals`: exact limits and the CLI's own output safety (gaps found by
mutation tests). Fake servers send raw values the real server would already escape,
so the CLI's second, independent layer is tested on its own."""

import argparse
import io
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from warden import approvals_cli

KEY = "edge-admin-key-0123456789abcdefgh"
ID1, ID2 = "a" * 32, "b" * 32


def item(approval_id: str, **extra: Any) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "agent_id": "agent-1",
        "tool": "send_email",
        "arguments": {"to": "x@example.com"},
        "warnings": [],
        "action_hash": "c" * 64,
        "expires_in_seconds": 60,
        **extra,
    }


def args(action: str, *ids: str, **flags: Any) -> argparse.Namespace:
    defaults = {"group": False, "yes": False, "warden_url": None, "agent": None, "tool": None}
    return argparse.Namespace(action=action, ids=list(ids), **{**defaults, **flags})


def run(
    monkeypatch: pytest.MonkeyPatch, answer: Any, namespace: argparse.Namespace, stdin: str = ""
) -> tuple[int, str, str]:
    monkeypatch.setattr(approvals_cli, "_call", lambda *a, **k: (200, answer))
    out, err = io.StringIO(), io.StringIO()
    code = approvals_cli.run(
        namespace, env={"WARDEN_ADMIN_KEY": KEY}, stdin=io.StringIO(stdin), out=out, err=err
    )
    return code, out.getvalue(), err.getvalue()


def test_output_is_ascii_even_if_the_server_isnt(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = item(ID1, agent_id="agent-é‮", tool="t\x1b[2J", warnings=["w​"])
    code, out, _ = run(monkeypatch, [raw], args("list"))
    assert code == 0 and out.isascii()
    assert "agent-\\u00e9\\u202e" in out and "t\\u001b[2J" in out and "w\\u200b" in out


def test_text_of_structures_has_sorted_keys() -> None:
    assert approvals_cli._text({"b": 1, "a": "é"}) == '{"a": "\\u00e9", "b": 1}'


def test_arguments_are_printed_sorted_with_two_space_indent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = item(ID1, arguments={"to": "x@example.com", "body": "hé"})
    _, out, _ = run(monkeypatch, [raw], args("list"))
    assert (
        '      arguments: {\n        "body": "h\\u00e9",\n        "to": "x@example.com"\n      }\n'
    ) in out


@pytest.mark.parametrize("group", [False, True])
def test_items_are_numbered_from_one(monkeypatch: pytest.MonkeyPatch, group: bool) -> None:
    answer: Any = [item(ID1), item(ID2)]
    if group:
        answer = {"groups": [{"approvals": answer}]}
    _, out, _ = run(monkeypatch, answer, args("list", group=group))
    assert f"  [1] {ID1}" in out and f"  [2] {ID2}" in out and "[3]" not in out


def test_explicit_streams_are_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """stdin/out/err given to run() are the ones used (not the process's own)."""
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))  # must NOT be read
    code, out, err = run(monkeypatch, [item(ID1)], args("reject", ID1), stdin="n\n")
    assert code == 1 and "Reject this action? [y/N]" in out and "Nothing changed." in out
    code, _, err = run(monkeypatch, [], args("list", "x"))
    assert code == 2 and "takes no ids" in err


def test_exactly_100_ids_pass_the_usage_check(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = [f"{i:032d}" for i in range(100)]
    code, _, err = run(monkeypatch, [], args("approve", *ids, yes=True))
    assert "at most" not in err
    assert code == 1 and "not pending" in err  # got as far as asking the server


class _Fixed(BaseHTTPRequestHandler):
    body = b""

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        self.send_response(200)
        self.send_header("content-length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a: Any) -> None:
        pass


@pytest.fixture
def fixed_server() -> Iterator[tuple[str, type[_Fixed]]]:
    handler = type("Handler", (_Fixed,), {})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", handler
    finally:
        server.shutdown()
        server.server_close()


def test_answer_of_exactly_32_mb_is_read(fixed_server: tuple[str, type[_Fixed]]) -> None:
    url, handler = fixed_server
    handler.body = b"[]" + b" " * (32 * 1024 * 1024 - 2)
    assert approvals_cli._call(url, KEY, "GET", "/v1/approvals") == (200, [])


def test_one_byte_over_32_mb_is_refused(fixed_server: tuple[str, type[_Fixed]]) -> None:
    url, handler = fixed_server
    handler.body = b"[]" + b" " * (32 * 1024 * 1024 - 1)
    with pytest.raises(approvals_cli._Unreachable, match="too large"):
        approvals_cli._call(url, KEY, "GET", "/v1/approvals")


# --- Broken connections and unsendable keys: a clear message, never a traceback ------------


@pytest.fixture
def raw_server() -> Iterator[tuple[str, list[bytes]]]:
    """Sends whatever bytes the test puts in the list, then closes the connection."""
    answer: list[bytes] = []

    class Raw(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            self.wfile.write(answer[0])
            self.close_connection = True

        def log_message(self, *a: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Raw)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", answer
    finally:
        server.shutdown()
        server.server_close()


def run_real(url: str, key: str = KEY) -> tuple[int, str]:
    err = io.StringIO()
    namespace = args("list", warden_url=url)
    code = approvals_cli.run(namespace, env={"WARDEN_ADMIN_KEY": key}, out=io.StringIO(), err=err)
    return code, err.getvalue()


CHUNKED = b"\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nshort"


@pytest.mark.parametrize(
    "raw",
    [
        b"",  # closed without answering
        b"garbage\r\n\r\n",  # not HTTP
        b"HTTP/1.1 200 OK" + CHUNKED,  # cut off while reading the answer
        b"HTTP/1.1 500 Oops" + CHUNKED,  # cut off while reading an error's body
    ],
)
def test_broken_answers_are_a_clear_error(raw_server: tuple[str, list[bytes]], raw: bytes) -> None:
    url, answer = raw_server
    answer.append(raw)
    code, err = run_real(url)
    assert code == 2 and f"can't reach Warden at {url}" in err


@pytest.mark.parametrize("bad", ["key\nX-Evil: 1", "key-\u20ac"])
def test_a_key_that_cant_be_sent_is_a_clear_error_without_the_key(bad: str) -> None:
    code, err = run_real("http://127.0.0.1:9", bad)
    assert code == 2 and "WARDEN_ADMIN_KEY contains characters" in err
    assert bad not in err and "Evil" not in err


@pytest.mark.parametrize("started", [False, True])
def test_a_slow_answer_says_so_and_not_unreachable(
    monkeypatch: pytest.MonkeyPatch, started: bool
) -> None:
    """No answer in time, before or after the first bytes of it."""
    monkeypatch.setattr(approvals_cli, "TIMEOUT_SECONDS", 0.2)
    with socket.create_server(("127.0.0.1", 0)) as server:
        accepted: list[socket.socket] = []

        def accept() -> None:
            connection, _ = server.accept()
            accepted.append(connection)
            if started:
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n[")

        thread = threading.Thread(target=accept)
        thread.start()
        code, err = run_real(f"http://127.0.0.1:{server.getsockname()[1]}")
        thread.join()
        accepted[0].close()
    assert code == 2 and "can't reach" not in err
    assert "didn't answer within 0.2 seconds" in err and "--agent" in err
