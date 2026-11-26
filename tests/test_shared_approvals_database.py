"""Several Warden servers on ONE approvals database: each approval still allows at most
one action, and every human decision holds on every server.
See docs/design/persistent-approvals.md."""

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from helpers import Clock

from warden.approvals import (
    Approval,
    ApprovalDB,
    ApprovalStore,
    DecideError,
    GroupDecideError,
    Rejected,
    StaleApproval,
    Status,
)
from warden.models import ActionRequest

H = "d" * 64


def act(n: int = 0) -> ActionRequest:
    return ActionRequest(agent_id="a", tool="t", arguments={"n": n})


def ask(store: ApprovalStore, n: int = 0, action_hash: str = H) -> str:
    approval_id = store.request(act(n), action_hash)
    assert approval_id is not None
    return approval_id


@pytest.fixture
def clock() -> Clock[float]:
    return Clock(1_800_000_000.0)


@pytest.fixture
def two(tmp_path: Path, clock: Clock[float]) -> tuple[ApprovalStore, ApprovalStore]:
    path = tmp_path / "a.db"
    return (
        ApprovalStore(db=ApprovalDB(path), clock=clock),
        ApprovalStore(db=ApprovalDB(path), clock=clock),
    )


Two = tuple[ApprovalStore, ApprovalStore]


def test_only_one_server_can_use_an_approval(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)
    assert b.use(approval_id, H, arguments=act().arguments) is Status.APPROVED
    assert a.use(approval_id, H) is Status.USED
    assert b.use(approval_id, H) is Status.USED


def test_racing_servers_get_one_allow_between_them(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    stores = [ApprovalStore(db=ApprovalDB(path)) for _ in range(6)]
    for n in range(10):
        action_hash = f"{n:064d}"
        approval_id = ask(stores[0], n, action_hash)
        stores[0].decide(approval_id, approve=True)
        barrier = threading.Barrier(len(stores))
        results: list[Status | None] = []

        def use(
            store: ApprovalStore,
            barrier: threading.Barrier = barrier,
            results: list[Status | None] = results,
            approval_id: str = approval_id,
            action_hash: str = action_hash,
        ) -> None:
            barrier.wait()
            results.append(store.use(approval_id, action_hash))

        threads = [threading.Thread(target=use, args=(s,)) for s in stores]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(Status.APPROVED) == 1
        assert len(results) == len(stores)


def before_next_save(store: ApprovalStore, other: Callable[[], Any]) -> None:
    """Run `other` (another server acting) between `store`'s check and its write."""
    db = store._db
    assert db is not None
    real = db.save_many

    def save_many(approvals: list[Approval]) -> None:
        db.save_many = real  # type: ignore[method-assign]
        other()
        real(approvals)

    db.save_many = save_many  # type: ignore[method-assign,assignment]


def test_use_loses_to_a_use_at_the_same_moment(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)
    other: list[Status | None] = []
    before_next_save(a, lambda: other.append(b.use(approval_id, H)))
    assert a.use(approval_id, H) is Status.USED
    assert other == [Status.APPROVED]


def test_use_loses_to_a_revoke_at_the_same_moment(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)
    before_next_save(a, lambda: b.decide(approval_id, approve=False))
    assert a.use(approval_id, H) is Status.DENIED


def test_use_that_lost_every_race_is_not_an_allow(two: Two) -> None:
    """Used AND restored by the other server in between: changed, so not this time."""
    a, b = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)

    def use_and_restore() -> None:
        assert b.use(approval_id, H) is Status.APPROVED
        b.restore(approval_id)

    before_next_save(a, use_and_restore)
    assert a.use(approval_id, H) is None
    assert a.use(approval_id, H) is Status.APPROVED  # next time it is
    assert b.use(approval_id, H) is Status.USED


def test_approve_loses_to_a_reject_at_the_same_moment(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    before_next_save(a, lambda: b.decide(approval_id, approve=False))
    with pytest.raises(StaleApproval):
        a.decide(approval_id, approve=True)
    assert a.use(approval_id, H) is Status.DENIED
    assert b.use(approval_id, H) is Status.DENIED


def test_group_approve_is_all_or_nothing_across_servers(two: Two) -> None:
    a, b = two
    ids = [ask(a, n, f"{n:064d}") for n in range(3)]
    before_next_save(a, lambda: b.decide(ids[2], approve=False))
    with pytest.raises(StaleApproval):
        a.decide_group(ids, approve=True)
    for store in two:
        assert {i.approval_id for i, _ in store.pending()} == set(ids[:2])


def test_decisions_are_seen_by_the_other_server(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    assert ask(b) == approval_id  # reused, not a second one
    a.decide(approval_id, approve=False)
    with pytest.raises(DecideError):
        b.decide(approval_id, approve=True)
    with pytest.raises(GroupDecideError):
        b.decide_group([approval_id], approve=True)
    assert b.use(approval_id, H) is Status.DENIED
    with pytest.raises(Rejected):
        ask(b)
    assert [a_.approval_id for a_, _, _ in b.rejections()] == [approval_id]
    b.lift(approval_id)
    assert a.rejections() == []
    assert ask(a) != approval_id


def test_revoke_is_seen_by_the_other_server(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)
    b.decide(approval_id, approve=False)
    assert a.use(approval_id, H) is Status.DENIED


def test_arguments_stay_in_the_server_that_was_asked(two: Two) -> None:
    a, b = two
    approval_id = ask(a)
    [(seen, _)] = b.pending()
    assert seen.arguments is None
    with pytest.raises(DecideError) as caught:
        b.decide(approval_id, approve=True)  # never approved blind
    assert caught.value.no_arguments
    assert a.pending()[0][0].arguments == {"n": 0}  # refreshing doesn't lose them


def test_same_action_on_both_servers_at_once_is_one_approval(two: Two) -> None:
    a, b = two
    other: list[str] = []
    before_next_save(a, lambda: other.append(ask(b)))
    assert [ask(a)] == other
    assert len(a.pending()) == 1


def test_a_server_never_deletes_what_another_renewed(two: Two, clock: Clock[float]) -> None:
    a, b = two
    approval_id = ask(a)
    b.pending()  # b knows it, with the old expiry
    clock.now += 800
    a.decide(approval_id, approve=True)  # a new full window
    clock.now += 200  # past the old expiry
    assert b.pending() == []
    assert a.use(approval_id, H) is Status.APPROVED


def test_expired_rows_that_cant_be_deleted_stay_unusable(
    two: Two, clock: Clock[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _ = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)
    clock.now += 10_000

    def broken(now: float) -> None:
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(a._db, "delete_expired", broken)
    assert a.use(approval_id, H) is None
    assert a.pending() == []


def test_locked_database_is_never_an_allow(two: Two, monkeypatch: pytest.MonkeyPatch) -> None:
    a, _ = two
    approval_id = ask(a)
    a.decide(approval_id, approve=True)
    assert a._db is not None
    path = a._db.path
    monkeypatch.setattr(a._db, "_connect", lambda: sqlite3.connect(path, timeout=0.05))
    for mode in ("IMMEDIATE", "EXCLUSIVE"):  # can't write; can't even read
        lock = sqlite3.connect(path, isolation_level=None)
        lock.execute(f"BEGIN {mode}")
        with pytest.raises(sqlite3.OperationalError):
            a.use(approval_id, H)
        lock.execute("ROLLBACK")
        lock.close()
    assert a.use(approval_id, H) is Status.APPROVED  # still there, once
    assert a.use(approval_id, H) is Status.USED
