"""`warden proxy` with an agent token: only a Warden that has proven itself decides."""

import json
import socket
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, live_server, shown
from proof import Proving, http_answer, raw_impostor, read_message, serving
from test_mcp_proxy import Session, call, calls_seen, echoed, make_config, run_session

from warden.agents import add_agent, load_agents
from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import NOT_PROVEN, WardenClient

TOKEN = "wdn_" + "P" * 43
PRIVATE = "argument-nobody-may-see"
ALLOW = b'{"decision": "allow", "reason": "evil"}'
PENDING = (
    b'{"decision": "require_approval", "reason": "ask", "approval_id": "appr-0123456789abcdef"}'
)


def always_allow(sock: socket.socket) -> None:
    read_message(sock)
    sock.sendall(http_answer(ALLOW))


def test_an_impostor_learns_nothing_and_the_tool_doesnt_run(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {"path": PRIVATE}))
        assert reply["result"]["isError"] is True
        assert NOT_PROVEN in reply["result"]["content"][0]["text"]

    with raw_impostor(always_allow) as (port, received):
        checker = WardenClient(f"http://127.0.0.1:{port}", token=TOKEN, timeout=2)
        session, _ = run_session(make_config(tmp_path), checker, script)
    assert calls_seen(session) == []
    assert b"POST /v1/hello " in received and received.count(b"POST ") == 1
    assert TOKEN.encode() not in received and PRIVATE.encode() not in received
    assert b"echo" not in received  # not even which tool


def test_a_failed_proof_ends_the_wait(tmp_path: Path) -> None:
    class Fake(Proving):
        secrets = (TOKEN,)
        questions = 0

        def answer(self) -> None:
            type(self).questions += 1
            if self.questions < 3:
                self.reply(200, PENDING)
            else:
                self.raw_reply(200, ALLOW, {})

    async def script(s: Session) -> None:
        started = time.monotonic()
        reply = await s.roundtrip(call("echo", {}))
        assert NOT_PROVEN in reply["result"]["content"][0]["text"]
        assert time.monotonic() - started < 10

    with serving(Fake) as url:
        approval = {"mode": "wait", "timeout_seconds": 30, "poll_seconds": 0.01}
        config = make_config(tmp_path, approval=approval)
        session, _ = run_session(config, WardenClient(url, token=TOKEN, timeout=2), script)
    assert calls_seen(session) == [] and Fake.questions == 3


def test_lost_connections_dont_end_the_wait(tmp_path: Path) -> None:
    class Fake(Proving):
        secrets = (TOKEN,)
        questions = 0

        def answer(self) -> None:
            type(self).questions += 1
            if self.questions in (3, 4):  # e.g. Warden restarts
                self.close_connection = True
            else:
                self.reply(200, PENDING if self.questions < 6 else ALLOW)

    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(call("echo", {"a": 1})))["arguments"] == {"a": 1}

    with serving(Fake) as url:
        run_session(make_config(tmp_path), WardenClient(url, token=TOKEN, timeout=2), script)
    assert Fake.questions == 6


@pytest.mark.parametrize("decision", ["allow", "deny", "require_approval"])
def test_with_a_real_warden(tmp_path: Path, decision: str) -> None:
    token = add_agent(tmp_path / "agents.json", "desktop")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"rules": [{"id": "r", "tool": "echo", "effect": decision}]}))
    app = create_app(
        policy,
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        admin_key=ADMIN_KEY,
        agents=load_agents(tmp_path / "agents.json"),
    )
    admin, headers = TestClient(app), {"X-Warden-Admin-Key": ADMIN_KEY}

    def human_approves() -> None:
        for _ in range(500):
            if items := admin.get("/v1/approvals", headers=headers).json():
                approval_id = items[0]["approval_id"]
                body = shown(admin, approval_id, headers)
                admin.post(f"/v1/approvals/{approval_id}/approve", headers=headers, json=body)
                return
            time.sleep(0.01)

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {"path": "/w"}))
        assert reply["result"].get("isError", False) is (decision == "deny")

    with live_server(app) as url:
        human = threading.Thread(target=human_approves if decision == "require_approval" else str)
        human.start()
        session, _ = run_session(make_config(tmp_path), WardenClient(url, token=token), script)
        human.join(timeout=10)
    assert len(calls_seen(session)) == (0 if decision == "deny" else 1)
