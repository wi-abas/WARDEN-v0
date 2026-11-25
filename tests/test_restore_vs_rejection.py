"""restore() undoes a use whose allow was never delivered. A human's newer "no" (a
rejection or a refused revoke) always wins over it, with and without a shared database."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY

from warden.api import create_app
from warden.approvals import (
    ApprovalDB,
    ApprovalStore,
    DecideError,
    GroupDecideError,
    Rejected,
    Status,
)
from warden.audit import SQLiteAuditLog
from warden.models import ActionRequest

H = "d" * 64
ACTION = ActionRequest(agent_id="a", tool="t", arguments={"n": 1})


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture(params=["memory", "one server", "two servers"])
def stores(
    request: pytest.FixtureRequest, tmp_path: Path, clock: Clock
) -> tuple[ApprovalStore, ApprovalStore]:
    """(the server the agent uses, the server the human decides on)."""
    if request.param == "memory":
        store = ApprovalStore(clock=clock)
        return store, store
    first = ApprovalStore(clock=clock, db=ApprovalDB(tmp_path / "a.db"))
    if request.param == "one server":
        return first, first
    return first, ApprovalStore(clock=clock, db=ApprovalDB(tmp_path / "a.db"))


Stores = tuple[ApprovalStore, ApprovalStore]


def ask(store: ApprovalStore) -> str:
    approval_id = store.request(ACTION, H)
    assert approval_id is not None
    return approval_id


def used(store: ApprovalStore) -> str:
    approval_id = ask(store)
    store.decide(approval_id, approve=True)
    assert store.use(approval_id, H) is Status.APPROVED
    return approval_id


def test_restore_still_works(stores: Stores) -> None:
    agent, _ = stores
    approval_id = used(agent)
    agent.restore(approval_id)
    assert agent.use(approval_id, H) is Status.APPROVED
    assert agent.use(approval_id, H) is Status.USED


def test_revoke_during_the_use_beats_restore(stores: Stores) -> None:
    agent, human = stores
    approval_id = used(agent)
    with pytest.raises(DecideError):
        human.decide(approval_id, approve=False)  # too late to stop the use itself
    agent.restore(approval_id)
    assert agent.use(approval_id, H) is Status.USED


def test_group_reject_during_the_use_beats_restore(stores: Stores) -> None:
    agent, human = stores
    approval_id = used(agent)
    with pytest.raises(GroupDecideError):
        human.decide_group([approval_id], approve=False)
    agent.restore(approval_id)
    assert agent.use(approval_id, H) is Status.USED


def test_approving_again_during_the_use_does_not_block_restore(stores: Stores) -> None:
    agent, human = stores
    approval_id = used(agent)
    with pytest.raises(DecideError):
        human.decide(approval_id, approve=True)
    agent.restore(approval_id)
    assert agent.use(approval_id, H) is Status.APPROVED


def test_rejecting_the_same_action_under_a_new_id_beats_restore(
    stores: Stores, clock: Clock
) -> None:
    agent, human = stores
    first = used(agent)
    second = ask(agent)
    assert second != first
    clock.now += 1
    human.decide(second, approve=False)
    agent.restore(first)
    assert agent.use(first, H) is Status.USED


def test_rejecting_the_same_action_after_the_restore_wins_too(stores: Stores, clock: Clock) -> None:
    agent, human = stores
    first = used(agent)
    second = ask(agent)
    agent.restore(first)
    clock.now += 1
    human.decide(second, approve=False)
    assert agent.use(first, H) is Status.DENIED
    with pytest.raises(Rejected):
        ask(agent)
    # Lifting only lets the agent ask: the beaten approval doesn't come back.
    human.lift(second)
    assert agent.use(first, H) is None
    assert ask(agent) not in {first, second}
    assert len(agent.pending()) == 1


def test_an_older_rejection_does_not_block_a_newer_approval(clock: Clock) -> None:
    store = ApprovalStore(clock=clock, rejection_window=lambda agent: 0)  # not sticky
    store.decide(ask(store), approve=False)
    clock.now += 1
    approval_id = ask(store)
    store.decide(approval_id, approve=True)
    assert store.use(approval_id, H) is Status.APPROVED


def test_another_server_cant_restore_a_use_it_did_not_make(tmp_path: Path) -> None:
    a = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"))
    b = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"))
    approval_id = used(a)
    b.restore(approval_id)
    assert b.use(approval_id, H) is Status.USED


def test_revoke_between_use_and_a_failing_audit_write(tmp_path: Path) -> None:
    """The real path: the audit write fails right after a human tried to revoke."""
    log = SQLiteAuditLog(tmp_path / "a.db")
    store = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"))
    app = create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=ADMIN_KEY)
    client = TestClient(app, raise_server_exceptions=False)
    body: dict[str, Any] = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "x"}}
    approval_id = client.post("/v1/evaluate", json=body).json()["approval_id"]
    store.decide(approval_id, approve=True)
    real = log.record

    def revoke_then_fail(entry: Any) -> None:
        with pytest.raises(DecideError):
            store.decide(approval_id, approve=False)
        raise OSError("disk full")

    log.record = revoke_then_fail  # type: ignore[method-assign]
    body["approval_id"] = approval_id
    assert client.post("/v1/evaluate", json=body).status_code == 503
    log.record = real  # type: ignore[method-assign]
    assert client.post("/v1/evaluate", json=body).json()["decision"] == "deny"
