"""An approval wait survives Warden being briefly unreachable (a restart), up to its own
timeout. Unreachable is never an allow, and outside a wait it is still a deny at once."""

import asyncio
import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from helpers import ADMIN_KEY, BASIC_POLICY

from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore
from warden.audit import SQLiteAuditLog
from warden.client import WardenClient
from warden.sdk import NotAllowed, run_guarded, run_guarded_async

APPROVAL = "appr-0123456789abcdef"
PENDING = {"decision": "require_approval", "reason": "ask", "approval_id": APPROVAL}
DROP = object()  # close the connection without an answer


class _Scripted(BaseHTTPRequestHandler):
    answers: list[Any]
    asked: int = 0

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        self.rfile.read(int(self.headers["content-length"]))
        cls = type(self)
        answer = cls.answers[min(cls.asked, len(cls.answers) - 1)]
        cls.asked += 1
        if answer is DROP:
            self.close_connection = True
            return
        body = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def scripted() -> Iterator[tuple[str, type[_Scripted]]]:
    handler: type[_Scripted] = type("Handler", (_Scripted,), {})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", handler
    server.shutdown()
    server.server_close()


def call(url: str, wait: float, is_async: bool) -> list[str]:
    ran: list[str] = []
    client = WardenClient(url, timeout=1)
    if is_async:

        async def tool() -> None:
            ran.append("x")

        asyncio.run(
            run_guarded_async(
                "t", {}, tool, client=client, wait_for_approval=wait, poll_seconds=0.02
            )
        )
    else:
        run_guarded(
            "t",
            {},
            lambda: ran.append("x"),
            client=client,
            wait_for_approval=wait,
            poll_seconds=0.02,
        )
    return ran


@pytest.mark.parametrize("is_async", [False, True])
def test_wait_survives_lost_answers(scripted: tuple[str, type[_Scripted]], is_async: bool) -> None:
    url, handler = scripted
    handler.answers = [PENDING, DROP, PENDING, DROP, DROP, {"decision": "allow", "reason": "ok"}]
    assert call(url, 5, is_async) == ["x"]


@pytest.mark.parametrize("is_async", [False, True])
def test_unreachable_until_the_timeout_is_not_allowed(
    scripted: tuple[str, type[_Scripted]], is_async: bool
) -> None:
    url, handler = scripted
    handler.answers = [PENDING, DROP]
    started = time.monotonic()
    with pytest.raises(NotAllowed, match="unreachable"):
        call(url, 0.3, is_async)
    assert 0.3 <= time.monotonic() - started < 3


def test_unreachable_before_any_approval_is_a_deny_at_once(
    scripted: tuple[str, type[_Scripted]],
) -> None:
    url, handler = scripted
    handler.answers = [DROP, PENDING]
    with pytest.raises(NotAllowed, match="unreachable"):
        call(url, 5, False)
    assert handler.asked == 1


def test_a_bad_answer_still_ends_the_wait(scripted: tuple[str, type[_Scripted]]) -> None:
    url, handler = scripted
    handler.answers = [PENDING, ["garbage"], {"decision": "allow", "reason": "ok"}]
    with pytest.raises(NotAllowed, match="unexpected answer"):
        call(url, 5, False)


def test_an_answer_lost_after_the_approval_was_used_never_runs_the_tool(
    scripted: tuple[str, type[_Scripted]],
) -> None:
    url, handler = scripted
    used = {"decision": "deny", "reason": "approval already used"}
    handler.answers = [PENDING, DROP, used]  # the lost one was the allow
    with pytest.raises(NotAllowed, match="already used"):
        call(url, 5, False)


def _serve(app: FastAPI, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    return server, thread


def test_wait_survives_a_real_restart(tmp_path: Path) -> None:
    def app() -> tuple[FastAPI, ApprovalStore]:
        store = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"))
        log = SQLiteAuditLog(tmp_path / "a.db")
        return create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=ADMIN_KEY), store

    first, store = app()
    server, thread = _serve(first, 0)
    port = server.servers[0].sockets[0].getsockname()[1]
    ran: list[str] = []
    problems: list[Exception] = []

    def agent() -> None:
        try:
            run_guarded(
                "send_email",
                {"to": "x"},
                lambda to: ran.append(to),
                client=WardenClient(f"http://127.0.0.1:{port}", "a"),
                wait_for_approval=15,
                poll_seconds=0.05,
            )
        except Exception as exc:
            problems.append(exc)

    worker = threading.Thread(target=agent)
    worker.start()
    while not store.pending():
        time.sleep(0.01)
    server.should_exit = True
    thread.join(timeout=10)
    time.sleep(0.3)  # really down for several polls
    second, store = app()
    server, thread = _serve(second, port)
    # The agent's next poll brings the arguments back; then the human approves.
    while not problems and not (store.pending() and store.pending()[0][0].arguments):
        time.sleep(0.01)
    if not problems:
        store.decide(store.pending()[0][0].approval_id, approve=True)
    worker.join(timeout=10)
    server.should_exit = True
    thread.join(timeout=10)
    assert problems == [] and ran == ["x"]
