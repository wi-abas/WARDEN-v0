"""Property test: random mixes of asking, single and group decisions and retries.

Invariants: each approval yields at most one allow, and the audit log's human
decisions match the store's final state."""

import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, shown, shown_hashes
from hypothesis import given, settings
from hypothesis import strategies as st

from warden.api import create_app
from warden.approvals import ApprovalStore, Status
from warden.audit import EventKind, SQLiteAuditLog, verify_chain
from warden.models import Decision

KEY = "prop-admin-key-0123456789abcdefgh"
ADMIN = {"X-Warden-Admin-Key": KEY}
ACTIONS = 6  # action n belongs to agent n % 2

ops = st.lists(
    st.one_of(
        st.tuples(st.just("ask"), st.integers(0, ACTIONS - 1)),
        st.tuples(st.just("retry"), st.integers(0, ACTIONS - 1)),
        st.tuples(st.just("single"), st.integers(0, ACTIONS - 1), st.booleans()),
        st.tuples(
            st.just("group"),
            st.lists(st.integers(0, ACTIONS - 1), min_size=1, max_size=4),
            st.booleans(),
        ),
    ),
    max_size=30,
)


def body(n: int, approval_id: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "agent_id": f"agent-{n % 2}",
        "tool": "send_email",
        "arguments": {"to": f"p{n}@example.com"},
    }
    if approval_id:
        data["approval_id"] = approval_id
    return data


@settings(max_examples=150, deadline=None)
@given(ops)
def test_group_and_single_decisions_stay_consistent(steps: list[tuple[Any, ...]]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log = SQLiteAuditLog(Path(tmp) / "a.db")
        store = ApprovalStore(ttl_seconds=10_000)
        client = TestClient(create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY))
        ids: dict[int, str] = {}
        allows: dict[str, int] = {}
        groups_ok = 0
        for step in steps:
            kind = step[0]
            if kind == "ask":
                answer = client.post("/v1/evaluate", json=body(step[1])).json()
                if answer["decision"] == "require_approval":
                    ids[step[1]] = answer["approval_id"]
            elif kind == "retry" and step[1] in ids:
                answer = client.post("/v1/evaluate", json=body(step[1], ids[step[1]])).json()
                if answer["decision"] == "allow":
                    allows[ids[step[1]]] = allows.get(ids[step[1]], 0) + 1
            elif kind == "single" and step[1] in ids:
                action = "approve" if step[2] else "deny"
                client.post(
                    f"/v1/approvals/{ids[step[1]]}/{action}",
                    headers=ADMIN,
                    json=shown(client, ids[step[1]], ADMIN),
                )
            elif kind == "group":
                chosen = list(dict.fromkeys(ids[n] for n in step[1] if n in ids))
                if chosen:
                    response = client.post(
                        "/v1/approvals/decide",
                        json={
                            "ids": chosen,
                            "action_hashes": shown_hashes(store, chosen),
                            "approve": step[2],
                        },
                        headers=ADMIN,
                    )
                    assert response.status_code in {200, 409}
                    groups_ok += response.status_code == 200

        # 1. Never more than one allow per approval.
        assert all(count == 1 for count in allows.values())

        # 2. The audit log matches the final state.
        events = list(reversed(log.recent_events(10_000)))
        last: dict[str, EventKind] = {}
        for e in events:
            if e.kind in {EventKind.APPROVAL_APPROVED, EventKind.APPROVAL_DENIED}:
                assert e.approval_id is not None
                last[e.approval_id] = e.kind
        allowed_ids = [d.approval_id for d in log.recent(10_000) if d.decision is Decision.ALLOW]
        for approval_id, approval in store._items.items():
            expected = {
                None: {Status.PENDING},
                EventKind.APPROVAL_APPROVED: {Status.APPROVED, Status.USED},
                EventKind.APPROVAL_DENIED: {Status.DENIED},
            }[last.get(approval_id)]
            assert approval.status in expected
            assert allowed_ids.count(approval_id) == (approval.status is Status.USED)
            assert allows.get(approval_id, 0) == (approval.status is Status.USED)
        group_events = [e for e in events if e.kind is EventKind.APPROVAL_GROUP_DECIDED]
        assert len(group_events) == groups_ok
        assert verify_chain(log.path).ok
