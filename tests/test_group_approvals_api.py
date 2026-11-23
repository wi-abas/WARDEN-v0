"""GET /v1/approvals?group=true and POST /v1/approvals/decide."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, shown, shown_hashes

from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore, Status
from warden.audit import AuditEvent, EventKind, SQLiteAuditLog, record_events, verify_chain

KEY = "group-admin-key-0123456789abcdef"
ADMIN = {"X-Warden-Admin-Key": KEY}


@pytest.fixture
def log(tmp_path: Path) -> SQLiteAuditLog:
    return SQLiteAuditLog(tmp_path / "audit.db")


@pytest.fixture
def store() -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900)


@pytest.fixture
def client(log: SQLiteAuditLog, store: ApprovalStore) -> TestClient:
    return TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))


def email(to: str, agent: str = "agent-1", approval_id: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"agent_id": agent, "tool": "send_email", "arguments": {"to": to}}
    if approval_id:
        body["approval_id"] = approval_id
    return body


def ask(client: TestClient, body: dict[str, Any]) -> dict[str, Any]:
    answer: dict[str, Any] = client.post("/v1/evaluate", json=body).json()
    return answer


def queue(client: TestClient, n: int, agent: str = "agent-1") -> list[str]:
    return [ask(client, email(f"p{i}@example.com", agent))["approval_id"] for i in range(n)]


def decide(client: TestClient, ids: list[str], approve: bool = True) -> Any:
    store = client.app.state.warden.approvals  # type: ignore[attr-defined]
    body = {"ids": ids, "action_hashes": shown_hashes(store, ids), "approve": approve}
    return client.post("/v1/approvals/decide", json=body, headers=ADMIN)


def events(log: SQLiteAuditLog, kind: EventKind) -> list[AuditEvent]:
    return [e for e in log.recent_events(1000) if e.kind is kind]


# --- Grouped list -------------------------------------------------------------------------


def test_grouped_list_shows_every_action(client: TestClient) -> None:
    ids = queue(client, 3)
    other = queue(client, 1, agent="agent-2")
    ask(client, {"agent_id": "agent-1", "tool": "delete_file", "arguments": {"path": "x"}})
    groups = client.get("/v1/approvals?group=true", headers=ADMIN).json()["groups"]
    keys = [(g["agent_id"], g["tool"], g["count"]) for g in groups]
    assert keys == [("agent-1", "send_email", 3), ("agent-2", "send_email", 1)]
    first = groups[0]["approvals"]
    assert [a["approval_id"] for a in first] == ids  # in the order they were created
    assert [a["arguments"] for a in first] == [{"to": f"p{i}@example.com"} for i in range(3)]
    assert groups[1]["approvals"][0]["approval_id"] == other[0]
    flat = client.get("/v1/approvals", headers=ADMIN).json()
    assert sorted(flat, key=lambda a: a["approval_id"]) == sorted(
        [a for g in groups for a in g["approvals"]], key=lambda a: a["approval_id"]
    )


def test_list_without_group_is_unchanged(client: TestClient) -> None:
    queue(client, 2)
    for url in ["/v1/approvals", "/v1/approvals?group=false"]:
        items = client.get(url, headers=ADMIN).json()
        assert isinstance(items, list) and len(items) == 2
        assert set(items[0]) == {
            "approval_id",
            "agent_id",
            "tool",
            "arguments",
            "warnings",
            "action_hash",
            "expires_in_seconds",
            "age_seconds",
        }


def test_grouped_list_escapes_hidden_characters(client: TestClient) -> None:
    ask(client, email("boss@example.com‮gro.live"))
    response = client.get("/v1/approvals?group=true", headers=ADMIN)
    assert "‮" not in response.text
    [item] = response.json()["groups"][0]["approvals"]
    assert item["arguments"]["to"] == "boss@example.com\\u202egro.live"
    assert item["warnings"]


def test_grouped_list_needs_the_admin_key(client: TestClient) -> None:
    assert client.get("/v1/approvals?group=true").status_code == 401
    assert client.get("/v1/approvals?group=maybe", headers=ADMIN).status_code == 422


# --- Group decisions ----------------------------------------------------------------------


def test_approve_a_group(client: TestClient, log: SQLiteAuditLog) -> None:
    ids = queue(client, 3)
    response = decide(client, ids)
    assert response.status_code == 200
    assert response.json() == {
        "status": "approved",
        "count": 3,
        "results": [{"approval_id": i, "status": "approved"} for i in ids],
    }
    for i, approval_id in enumerate(ids):
        body = email(f"p{i}@example.com", approval_id=approval_id)
        assert ask(client, body)["decision"] == "allow"
        assert ask(client, body)["decision"] == "deny"  # used up
    # One event per approval, plus one for the group; the chain is intact.
    assert [e.approval_id for e in events(log, EventKind.APPROVAL_APPROVED)][::-1] == ids
    [group] = events(log, EventKind.APPROVAL_GROUP_DECIDED)
    assert group.reason == f"group of 3 approved by admin: {' '.join(ids)}"
    assert (group.agent_id, group.tool) == ("agent-1", "send_email")
    assert verify_chain(log.path).ok


def test_an_approved_id_only_fits_its_own_action(client: TestClient) -> None:
    ids = queue(client, 2)
    decide(client, ids)
    swapped = email("p1@example.com", approval_id=ids[0])
    assert ask(client, swapped)["decision"] == "deny"
    other_agent = email("p0@example.com", agent="agent-2", approval_id=ids[0])
    assert ask(client, other_agent)["decision"] == "deny"
    assert ask(client, email("p0@example.com", approval_id=ids[0]))["decision"] == "allow"


def test_reject_a_group(client: TestClient, log: SQLiteAuditLog) -> None:
    ids = queue(client, 3)
    response = decide(client, ids, approve=False)
    assert response.json()["status"] == "denied"
    for i, approval_id in enumerate(ids):
        answer = ask(client, email(f"p{i}@example.com", approval_id=approval_id))
        assert answer == {**answer, "decision": "deny", "reason": "denied by a human"}
    assert len(events(log, EventKind.APPROVAL_DENIED)) == 3
    [group] = events(log, EventKind.APPROVAL_GROUP_DECIDED)
    assert group.reason.startswith("group of 3 rejected by admin")


def test_an_approval_created_after_the_list_is_not_affected(client: TestClient) -> None:
    queue(client, 2)
    listed = client.get("/v1/approvals?group=true", headers=ADMIN).json()
    ids = [a["approval_id"] for a in listed["groups"][0]["approvals"]]
    [late] = [ask(client, email("late@example.com"))["approval_id"]]
    assert decide(client, ids).status_code == 200
    pending = client.get("/v1/approvals", headers=ADMIN).json()
    assert [a["approval_id"] for a in pending] == [late]


def assert_nothing_changed(client: TestClient, before: Any) -> None:
    assert client.get("/v1/approvals", headers=ADMIN).json() == before


@pytest.mark.parametrize("problem", ["unknown", "used", "denied", "revoked", "approved"])
def test_one_bad_id_changes_nothing(
    client: TestClient, store: ApprovalStore, log: SQLiteAuditLog, problem: str
) -> None:
    ids = queue(client, 3)
    bad = ask(client, email("bad@example.com"))["approval_id"] if problem != "unknown" else "z" * 32
    if problem != "unknown":
        client.post(f"/v1/approvals/{bad}/approve", headers=ADMIN, json=shown(client, bad, ADMIN))
    if problem == "used":
        assert ask(client, email("bad@example.com", approval_id=bad))["decision"] == "allow"
    if problem in {"denied", "revoked"}:
        client.post(f"/v1/approvals/{bad}/deny", headers=ADMIN, json=shown(client, bad, ADMIN))
    before = client.get("/v1/approvals", headers=ADMIN).json()
    approved_before = len(events(log, EventKind.APPROVAL_APPROVED))
    response = decide(client, [ids[0], bad, ids[1], ids[2]])
    assert response.status_code == 409
    reason = "not found or expired" if problem == "unknown" else "already decided"
    assert response.json() == {
        "error": "nothing changed: some approvals can't be decided",
        "failed": [{"id": bad, "reason": reason}],
    }
    assert_nothing_changed(client, before)
    assert all(store._items[i].status is Status.PENDING for i in ids)
    assert len(events(log, EventKind.APPROVAL_APPROVED)) == approved_before
    assert not events(log, EventKind.APPROVAL_GROUP_DECIDED)
    [failed] = [e for e in events(log, EventKind.APPROVAL_DECIDE_FAILED) if e.http_status == 409]
    assert failed.reason == "group decision refused: 1 of 4 ids failed, nothing changed"


def test_expired_id_changes_nothing(tmp_path: Path) -> None:
    now = [1000.0]
    store = ApprovalStore(ttl_seconds=900, clock=lambda: now[0])
    client = TestClient(
        create_app(
            BASIC_POLICY,
            audit_log=SQLiteAuditLog(tmp_path / "a.db"),
            approvals=store,
            admin_key=KEY,
        )
    )
    [old] = queue(client, 1)
    now[0] += 800
    fresh = [ask(client, email(f"n{i}@example.com"))["approval_id"] for i in range(2)]
    now[0] += 200
    response = decide(client, [*fresh, old])
    assert response.status_code == 409
    assert response.json()["failed"] == [{"id": old, "reason": "not found or expired"}]
    assert all(store._items[i].status is Status.PENDING for i in fresh)


def test_wrong_agent_changes_nothing(client: TestClient, store: ApprovalStore) -> None:
    mine = queue(client, 2)
    [theirs] = queue(client, 1, agent="agent-2")
    response = decide(client, [*mine, theirs])
    assert response.json()["failed"] == [
        {"id": theirs, "reason": "different agent or tool than the rest of the group"}
    ]
    assert all(a.status is Status.PENDING for a in store._items.values())


def test_wrong_tool_changes_nothing(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    rules = [{"id": f"ask-{t}", "tool": t, "effect": "require_approval"} for t in ("mail", "pay")]
    policy.write_text(json.dumps({"rules": rules}))
    store = ApprovalStore(ttl_seconds=900)
    client = TestClient(
        create_app(
            policy, audit_log=SQLiteAuditLog(tmp_path / "a.db"), approvals=store, admin_key=KEY
        )
    )
    ids = [
        ask(client, {"agent_id": "a", "tool": tool, "arguments": {"n": n}})["approval_id"]
        for n, tool in enumerate(["mail", "mail", "pay"])
    ]
    response = decide(client, ids)
    assert response.status_code == 409
    assert response.json()["failed"] == [
        {"id": ids[2], "reason": "different agent or tool than the rest of the group"}
    ]
    assert all(a.status is Status.PENDING for a in store._items.values())


@pytest.mark.parametrize(
    "body",
    [
        {"ids": [], "approve": True},
        {"ids": [f"{i:032d}" for i in range(101)], "approve": True},
        {"ids": ["a" * 32, "a" * 32], "approve": True},  # duplicate
        {"ids": ["short"], "approve": True},
        {"ids": ["a" * 32 + "‮"], "approve": True},
        {"ids": ["a" * 32], "approve": "true"},  # strict: a real boolean
        {"ids": ["a" * 32], "approve": 1},
        {"ids": "a" * 32, "approve": True},
        {"ids": ["a" * 32]},
        {"ids": ["a" * 32], "approve": True, "filter": "agent-1"},  # no filters, ever
        {"approve": True, "agent_id": "agent-1"},
    ],
)
def test_malformed_group_bodies_are_refused(client: TestClient, body: Any) -> None:
    ids = queue(client, 1)
    response = client.post("/v1/approvals/decide", json=body, headers=ADMIN)
    assert response.status_code == 422
    assert response.json()["decision"] == "deny"
    assert "a" * 32 not in response.text  # never echoes the input
    assert client.get("/v1/approvals", headers=ADMIN).json()[0]["approval_id"] == ids[0]


def test_duplicate_json_key_is_refused(client: TestClient) -> None:
    [good] = queue(client, 1)
    raw = f'{{"ids": ["{good}"], "approve": false, "approve": true}}'
    response = client.post(
        "/v1/approvals/decide",
        content=raw,
        headers={**ADMIN, "content-type": "application/json"},
    )
    assert response.status_code == 422


def test_hundred_ids_work(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            BASIC_POLICY,
            audit_log=SQLiteAuditLog(tmp_path / "a.db"),
            approvals=ApprovalStore(ttl_seconds=900, max_pending=200),
            admin_key=KEY,
        )
    )
    ids = queue(client, 100)
    assert decide(client, ids).json()["count"] == 100


def test_group_decision_needs_the_admin_key(client: TestClient, store: ApprovalStore) -> None:
    ids = queue(client, 2)
    for headers in [{}, {"X-Warden-Admin-Key": "wrong"}]:
        response = client.post(
            "/v1/approvals/decide", json={"ids": ids, "approve": True}, headers=headers
        )
        assert response.status_code == 401
    assert all(a.status is Status.PENDING for a in store._items.values())


class BrokenLog(SQLiteAuditLog):
    def record_events(self, events: list[AuditEvent]) -> None:
        raise OSError("disk full")


def test_audit_failure_approves_nothing(tmp_path: Path) -> None:
    log = BrokenLog(tmp_path / "a.db")
    store = ApprovalStore(ttl_seconds=900)
    client = TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))
    ids = [ask(client, email(f"p{n}@example.com"))["approval_id"] for n in range(3)]
    response = decide(client, ids)
    assert response.status_code == 503
    assert response.json() == {"error": "audit log unavailable, nothing changed"}
    assert all(a.status is Status.PENDING for a in store._items.values())


def test_group_events_are_one_transaction(tmp_path: Path) -> None:
    """If the last event can't be written, none of them are."""
    log = SQLiteAuditLog(tmp_path / "a.db")
    good = AuditEvent.now(EventKind.APPROVAL_APPROVED, "ok")
    bad = AuditEvent.now(EventKind.APPROVAL_APPROVED, "\ud800")  # can't be encoded
    with pytest.raises(UnicodeEncodeError):
        log.record_events([good, bad])
    assert log.recent_events() == []


def test_restart_then_group_approve_is_refused(tmp_path: Path) -> None:
    def server() -> TestClient:
        return TestClient(
            create_app(
                BASIC_POLICY,
                audit_log=SQLiteAuditLog(tmp_path / "a.db"),
                approvals=ApprovalStore(db=ApprovalDB(tmp_path / "a.db"), ttl_seconds=900),
                admin_key=KEY,
            )
        )

    ids = queue(server(), 2)
    after = server()
    response = decide(after, ids)
    assert response.status_code == 409
    reason = "arguments not available yet (Warden restarted)"
    assert response.json()["failed"] == [{"id": i, "reason": reason} for i in ids]
    ask(after, email("p0@example.com"))
    ask(after, email("p1@example.com"))  # both asked again: arguments are back
    assert decide(after, ids).status_code == 200


def test_refused_groups_are_logged_within_the_rejection_limit(
    client: TestClient, log: SQLiteAuditLog
) -> None:
    client.app.state.warden.rejections_per_minute = 2  # type: ignore[attr-defined]
    for _ in range(5):
        assert decide(client, ["y" * 32]).status_code == 409
    assert len(events(log, EventKind.APPROVAL_DECIDE_FAILED)) == 2


class ListLog:
    """Not an SQLiteAuditLog: events are written one by one."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record_event(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_other_audit_logs_get_every_event() -> None:
    log = ListLog()
    one, two = (AuditEvent.now(EventKind.APPROVAL_APPROVED, r) for r in "ab")
    record_events(log, [one, two])  # type: ignore[arg-type]
    assert log.events == [one, two]
