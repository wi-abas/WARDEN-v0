"""examples/agent.py against a real Warden server, with a pretend human approving."""

import importlib.util
import threading
import time
from pathlib import Path
from types import ModuleType

import pytest
import uvicorn
from fastapi.testclient import TestClient

from warden.api import create_app
from warden.audit import SQLiteAuditLog

EXAMPLES = Path(__file__).parent.parent / "examples"
KEY = "test-admin-key-" + "x" * 20


def load_agent() -> ModuleType:
    spec = importlib.util.spec_from_file_location("agent", EXAMPLES / "agent.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def server(tmp_path: Path):
    app = create_app(
        EXAMPLES / "demo-policy.json",
        audit_log=SQLiteAuditLog(tmp_path / "audit.db"),
        admin_key=KEY,
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield app, f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def test_agent_runs_allowed_blocks_denied_and_waits_for_approval(server) -> None:
    app, url = server
    admin = TestClient(app)

    def pretend_human() -> None:
        for _ in range(500):
            pending = admin.get("/v1/approvals", headers={"X-Warden-Admin-Key": KEY}).json()
            if pending:
                approval_id = pending[0]["approval_id"]
                admin.post(
                    f"/v1/approvals/{approval_id}/approve", headers={"X-Warden-Admin-Key": KEY}
                )
                return
            time.sleep(0.01)

    human = threading.Thread(target=pretend_human)
    human.start()
    outcomes = load_agent().main(url=url, poll_every=0.05)
    human.join(timeout=5)
    assert outcomes == [
        "ran read_file",
        "blocked delete_file",
        "ran send_invoice",
        "ran send_invoice",  # after the human approved
    ]


def test_unreachable_warden_means_not_run() -> None:
    agent = load_agent()
    ran = []
    with pytest.raises(agent.NotAllowed, match="unreachable"):
        agent.guarded("read_file", {"path": "/x"}, ran.append, url="http://127.0.0.1:9")
    assert ran == []


def test_gives_up_waiting_without_running(server) -> None:
    _, url = server
    agent = load_agent()
    ran = []
    with pytest.raises(agent.NotAllowed, match="gave up"):
        agent.guarded(
            "send_invoice",
            {"to": "acme", "amount": 9999},
            lambda **kw: ran.append(kw),
            url=url,
            wait_seconds=0.2,
            poll_every=0.05,
        )
    assert ran == []
