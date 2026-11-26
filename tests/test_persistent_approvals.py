"""Persistent approvals: state survives a restart; arguments never touch disk;
single use, expiry, revocation and action binding still hold."""

import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, shown

import warden.api
from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore, Status
from warden.audit import SQLiteAuditLog
from warden.models import ActionRequest
from warden.settings import Settings

ADMIN = {"X-Warden-Admin-Key": ADMIN_KEY}
PRIVATE_TO = "ceo-private-address@example.com"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


class Warden:
    """One Warden 'process'. restart() builds a new one on the same database."""

    def __init__(self, tmp_path: Path, clock: Clock) -> None:
        self.path = tmp_path / "audit.db"
        self.clock = clock
        self.start()

    def start(self) -> None:
        self.store = ApprovalStore(db=ApprovalDB(self.path), clock=self.clock)
        app = create_app(
            BASIC_POLICY,
            audit_log=SQLiteAuditLog(self.path),
            approvals=self.store,
            admin_key=ADMIN_KEY,
        )
        self.client = TestClient(app, raise_server_exceptions=False)

    restart = start

    def ask(self, to: str = PRIVATE_TO, approval_id: str | None = None, agent: str = "a") -> Any:
        body: dict[str, Any] = {"agent_id": agent, "tool": "send_email", "arguments": {"to": to}}
        if approval_id:
            body["approval_id"] = approval_id
        return self.client.post("/v1/evaluate", json=body).json()

    def decide(self, approval_id: str, action: str = "approve") -> Any:
        return self.client.post(
            f"/v1/approvals/{approval_id}/{action}",
            headers=ADMIN,
            json=shown(self.client, approval_id, ADMIN),
        )

    def pending(self) -> Any:
        return self.client.get("/v1/approvals", headers=ADMIN).json()


@pytest.fixture
def w(tmp_path: Path) -> Warden:
    return Warden(tmp_path, Clock())


def test_arguments_never_reach_the_database(w: Warden) -> None:
    w.ask()
    assert PRIVATE_TO.encode() not in w.path.read_bytes()
    assert stat.S_IMODE(w.path.stat().st_mode) == 0o600


def test_pending_survives_restart_but_cant_be_approved_blind(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.restart()
    [item] = w.pending()
    assert item["approval_id"] == approval_id and item["arguments"] is None
    assert "Warden restarted" in item["warnings"][0]
    response = w.decide(approval_id)
    assert response.status_code == 409 and "not available" in response.json()["error"]
    # The agent asks again with the same action: same approval, arguments are back.
    assert w.ask()["approval_id"] == approval_id
    assert w.pending()[0]["arguments"] == {"to": PRIVATE_TO}
    assert w.decide(approval_id).status_code == 200
    assert w.ask(approval_id=approval_id)["decision"] == "allow"


def test_poll_with_id_after_restart_restores_arguments(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.restart()
    assert w.ask(approval_id=approval_id)["decision"] == "require_approval"
    assert w.pending()[0]["arguments"] == {"to": PRIVATE_TO}


def test_a_different_action_cant_fill_in_the_arguments(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.restart()
    assert w.ask(to="attacker@evil.net", approval_id=approval_id)["decision"] == "deny"
    assert w.pending()[0]["arguments"] is None  # still unknown, not the attacker's


def test_another_agent_cant_fill_in_the_arguments(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.restart()
    assert w.ask(approval_id=approval_id, agent="b")["decision"] == "deny"
    assert w.pending()[0]["arguments"] is None


def test_approved_before_restart_is_usable_once_after(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    assert w.decide(approval_id).status_code == 200
    w.restart()
    assert w.ask(approval_id=approval_id)["decision"] == "allow"
    w.restart()
    replay = w.ask(approval_id=approval_id)
    assert replay["decision"] == "deny" and replay["reason"] == "approval already used"


def test_revocation_survives_restart(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.decide(approval_id)
    assert w.decide(approval_id, "deny").status_code == 200
    w.restart()
    answer = w.ask(approval_id=approval_id)
    assert answer["decision"] == "deny" and answer["reason"] == "denied by a human"


def test_denying_blind_is_allowed(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.restart()
    assert w.decide(approval_id, "deny").status_code == 200


def test_expired_approvals_are_gone_after_restart(w: Warden) -> None:
    approval_id = w.ask()["approval_id"]
    w.decide(approval_id)
    w.clock.now += 15 * 60 + 1
    w.restart()
    assert w.pending() == []
    assert w.ask(approval_id=approval_id)["reason"] == "approval not valid"
    rows = sqlite3.connect(w.path).execute("SELECT COUNT(*) FROM approvals").fetchone()
    assert rows == (0,)


def test_expiry_while_running_deletes_rows(w: Warden) -> None:
    w.ask()
    w.clock.now += 15 * 60 + 1
    assert w.pending() == []
    rows = sqlite3.connect(w.path).execute("SELECT COUNT(*) FROM approvals").fetchone()
    assert rows == (0,)


# --- Failures fail closed -------------------------------------------------------------


class BrokenDB(ApprovalDB):
    broken = False

    def save(self, approval: Any) -> None:
        if self.broken:
            raise sqlite3.OperationalError("disk I/O error")
        super().save(approval)

    def delete(self, approval_ids: list[str]) -> None:
        raise sqlite3.OperationalError("locked")


def test_failed_writes_change_nothing(tmp_path: Path) -> None:
    db = BrokenDB(tmp_path / "a.db")
    clock = Clock()
    store = ApprovalStore(db=db, clock=clock)
    action = ActionRequest(agent_id="a", tool="t", arguments={"x": 1})
    approval_id = store.request(action, "d" * 64)
    assert approval_id is not None
    db.broken = True
    with pytest.raises(sqlite3.Error):
        store.request(ActionRequest(agent_id="a", tool="t", arguments={"x": 2}), "e" * 64)
    with pytest.raises(sqlite3.Error):
        store.decide(approval_id, approve=True)
    assert store.pending()[0][0].status is Status.PENDING  # not approved
    db.broken = False
    store.decide(approval_id, approve=True)
    db.broken = True
    with pytest.raises(sqlite3.Error):
        store.use(approval_id, "d" * 64)
    db.broken = False
    assert store.use(approval_id, "d" * 64) is Status.APPROVED  # wasn't burned
    db.broken = True
    store.restore(approval_id)  # can't persist the undo: stays used (fail closed)
    assert store.use(approval_id, "d" * 64) is Status.USED
    clock.now += 10_000
    assert store.pending() == []  # a failed delete of expired rows is harmless


def test_failed_write_through_the_api_is_deny(tmp_path: Path) -> None:
    db = BrokenDB(tmp_path / "a.db")
    db.broken = True
    app = create_app(
        BASIC_POLICY,
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        approvals=ApprovalStore(db=db),
        admin_key=ADMIN_KEY,
    )
    client = TestClient(app, raise_server_exceptions=False)
    body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "x"}}
    response = client.post("/v1/evaluate", json=body)
    assert response.status_code == 500 and response.json()["decision"] == "deny"


def test_symlinked_database_refused(tmp_path: Path) -> None:
    (tmp_path / "real.db").touch()
    (tmp_path / "link.db").symlink_to(tmp_path / "real.db")
    with pytest.raises(ValueError, match="symlink"):
        ApprovalDB(tmp_path / "link.db")


def test_main_persists_approvals_in_the_audit_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: apps.append(app))
    settings = Settings(
        policy=BASIC_POLICY, audit_db=tmp_path / "a.db", admin_key="k" * 32, no_auth=True
    )
    warden.api.main(settings)
    client = TestClient(apps[0], raise_server_exceptions=False)
    body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "x"}}
    approval_id = client.post("/v1/evaluate", json=body).json()["approval_id"]
    warden.api.main(settings)  # "restart"
    assert apps[1].state.warden.approvals.pending()[0][0].approval_id == approval_id
