"""Re-audit of group approvals: trying to get an action approved that the human didn't
mean to approve, or to make the record disagree with what happened."""

import io
import json
import sqlite3
import threading
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server, shown, shown_hashes

from warden import approvals_cli
from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore, Status
from warden.audit import EventKind, SQLiteAuditLog, verify_chain
from warden.cli import main

KEY = "attack-admin-key-0123456789abcdef"
ADMIN = {"X-Warden-Admin-Key": KEY}


def email(n: int, agent: str = "a", approval_id: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_id": agent,
        "tool": "send_email",
        "arguments": {"to": f"p{n}@x.com"},
    }
    if approval_id:
        body["approval_id"] = approval_id
    return body


def post(url: str, path: str, body: Any, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(  # noqa: S310 (local test server)
        url + path,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.loads(error.read())


def test_racing_overlapping_groups_over_http(tmp_path: Path) -> None:
    """Groups that share ids, single decisions and agent retries, all at once, over real
    HTTP: overlapping groups can't both win, nothing is allowed twice, and the audit log
    agrees with the final state."""
    log = SQLiteAuditLog(tmp_path / "a.db")
    store = ApprovalStore(ttl_seconds=900)
    app = create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY)
    with live_server(app) as url:
        ids = [post(url, "/v1/evaluate", email(n))[1]["approval_id"] for n in range(6)]
        results: dict[str, int] = {}
        allows: list[str] = []
        barrier = threading.Barrier(7)

        def group(name: str, members: list[int], approve: bool) -> None:
            barrier.wait()
            chosen = [ids[m] for m in members]
            body = {"ids": chosen, "action_hashes": shown_hashes(store, chosen), "approve": approve}
            results[name] = post(url, "/v1/approvals/decide", body, ADMIN)[0]

        def retry(n: int) -> None:
            barrier.wait()
            for _ in range(15):
                status, answer = post(url, "/v1/evaluate", email(n, approval_id=ids[n]))
                if answer["decision"] == "allow":
                    allows.append(ids[n])

        threads = [
            threading.Thread(target=group, args=("g1", [0, 1, 2, 3], True)),
            threading.Thread(target=group, args=("g2", [2, 3, 4, 5], False)),
            threading.Thread(target=group, args=("g3", [3], True)),
            *[threading.Thread(target=retry, args=(n,)) for n in (0, 2, 3, 5)],
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # They all share id 3: exactly one of the three groups wins.
    assert sorted(results.values()) == [200, 409, 409]
    assert len(allows) == len(set(allows))
    group_events = [
        e for e in log.recent_events(1000) if e.kind is EventKind.APPROVAL_GROUP_DECIDED
    ]
    assert len(group_events) == 1
    decided = {
        e.approval_id: e.kind
        for e in log.recent_events(1000)
        if e.kind in {EventKind.APPROVAL_APPROVED, EventKind.APPROVAL_DENIED}
    }
    for approval_id, approval in store._items.items():
        kind = decided.get(approval_id)
        if kind is None:
            assert approval.status is Status.PENDING
        elif kind is EventKind.APPROVAL_APPROVED:
            assert approval.status in {Status.APPROVED, Status.USED}
        else:
            assert approval.status is Status.DENIED
        assert (approval_id in allows) == (approval.status is Status.USED)
    assert verify_chain(log.path).ok


def test_action_queued_while_the_human_reads_is_not_included(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The agent queues a near-identical action while the CLI is waiting for "y"."""
    store = ApprovalStore(ttl_seconds=900)
    app = create_app(
        BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), approvals=store, admin_key=KEY
    )
    client = TestClient(app)
    ids = [client.post("/v1/evaluate", json=email(n)).json()["approval_id"] for n in range(2)]
    sneaky: list[str] = []
    real_confirm = approvals_cli._confirm

    def agent_acts_meanwhile(*args: Any) -> bool:
        body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "evil@x.com"}}
        sneaky.append(client.post("/v1/evaluate", json=body).json()["approval_id"])
        return real_confirm(*args)

    monkeypatch.setattr(approvals_cli, "_confirm", agent_acts_meanwhile)
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    with live_server(app) as url:
        assert main(["approvals", "approve", *ids, "--warden-url", url]) == 0
    out = capsys.readouterr().out
    assert "evil@x.com" not in out
    assert [store._items[i].status for i in ids] == [Status.APPROVED] * 2
    assert store._items[sneaky[0]].status is Status.PENDING


def test_storage_failure_after_audit_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit written, then saving the approvals fails: nothing is approved, and the log
    says the decision was NOT applied (it never claims an approval that didn't happen)."""
    log = SQLiteAuditLog(tmp_path / "a.db")
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(db=db, ttl_seconds=900)
    client = TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))
    ids = [client.post("/v1/evaluate", json=email(n)).json()["approval_id"] for n in range(2)]

    def locked(approvals: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "save_many", locked)
    body = {"ids": ids, "action_hashes": shown_hashes(store, ids), "approve": True}
    response = client.post("/v1/approvals/decide", json=body, headers=ADMIN)
    assert response.status_code == 503
    assert all(store._items[i].status is Status.PENDING for i in ids)
    for i in ids:
        assert (
            client.post("/v1/evaluate", json=email(ids.index(i), approval_id=i)).json()["decision"]
            == "require_approval"
        )
    [failed] = [e for e in log.recent_events() if e.kind is EventKind.APPROVAL_DECIDE_FAILED]
    assert failed.reason.startswith("group decision NOT applied")
    assert all(i in failed.reason for i in ids)


def test_audit_failure_records_no_not_applied_event(tmp_path: Path) -> None:
    class Broken(SQLiteAuditLog):
        def record_events(self, events: Any) -> None:
            raise OSError("disk full")

    log = Broken(tmp_path / "a.db")
    store = ApprovalStore(ttl_seconds=900)
    client = TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))
    [approval_id] = [client.post("/v1/evaluate", json=email(0)).json()["approval_id"]]
    body = {
        "ids": [approval_id],
        "action_hashes": shown_hashes(store, [approval_id]),
        "approve": True,
    }
    response = client.post("/v1/approvals/decide", json=body, headers=ADMIN)
    assert response.status_code == 503
    assert not log.recent_events()  # the not-applied event goes through record_events too


@pytest.mark.parametrize(
    "ids",
    [
        ["a" * 65],  # longer than any approval id
        ["a" * 31 + "а"],  # Cyrillic look-alike
        ["a" * 32 + "\n"],
        ["../" + "a" * 32],
        [None],
        [{"$ne": ""}],
        [["a" * 32]],
    ],
)
def test_malformed_ids(tmp_path: Path, ids: list[Any]) -> None:
    client = TestClient(
        create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=KEY)
    )
    response = client.post(
        "/v1/approvals/decide", json={"ids": ids, "approve": True}, headers=ADMIN
    )
    assert response.status_code == 422 and response.json()["decision"] == "deny"


def test_oversized_body_is_refused_before_reading(tmp_path: Path) -> None:
    client = TestClient(
        create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=KEY)
    )
    body = {"ids": ["a" * 64] * 2000, "approve": True}
    response = client.post("/v1/approvals/decide", json=body, headers=ADMIN)
    assert response.status_code == 413


def test_query_filters_are_not_a_thing(tmp_path: Path) -> None:
    """Extra query parameters can't turn a decision into "everything matching"."""
    store = ApprovalStore(ttl_seconds=900)
    client = TestClient(
        create_app(
            BASIC_POLICY,
            audit_log=SQLiteAuditLog(tmp_path / "a.db"),
            approvals=store,
            admin_key=KEY,
        )
    )
    ids = [client.post("/v1/evaluate", json=email(n)).json()["approval_id"] for n in range(3)]
    response = client.post(
        "/v1/approvals/decide?agent_id=a&all=true",
        json={"ids": ids[:1], "action_hashes": shown_hashes(store, ids[:1]), "approve": True},
        headers=ADMIN,
    )
    assert response.json()["count"] == 1
    assert [store._items[i].status for i in ids[1:]] == [Status.PENDING] * 2


@pytest.mark.parametrize("action", ["approve", "deny"])
def test_single_decision_storage_failure_after_audit_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """The same gap for single decisions: audited, then saving fails. Nothing changes,
    and the log says the decision was NOT applied."""
    log = SQLiteAuditLog(tmp_path / "a.db")
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(db=db, ttl_seconds=900)
    client = TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))
    approval_id = client.post("/v1/evaluate", json=email(0)).json()["approval_id"]

    def locked(approvals: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "save_many", locked)
    response = client.post(
        f"/v1/approvals/{approval_id}/{action}",
        headers=ADMIN,
        json=shown(client, approval_id, ADMIN),
    )
    assert response.status_code == 503
    assert store._items[approval_id].status is Status.PENDING
    kinds = [e.kind for e in reversed(log.recent_events())]
    assert kinds[-1] is EventKind.APPROVAL_DECIDE_FAILED
    [failed] = [e for e in log.recent_events() if e.kind is EventKind.APPROVAL_DECIDE_FAILED]
    assert failed.reason.startswith("decision NOT applied")
    assert failed.approval_id == approval_id
