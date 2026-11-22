"""Group decisions in the approval store: all or nothing, one agent and tool, and each
approval still an ordinary single-use approval bound to its own action."""

import sqlite3
import threading
from pathlib import Path

import pytest

from warden.approvals import (
    MAX_GROUP,
    Approval,
    ApprovalDB,
    ApprovalStore,
    GroupDecideError,
    GroupReason,
    Status,
)
from warden.models import ActionRequest


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def action(n: int, agent: str = "a", tool: str = "send_email") -> ActionRequest:
    return ActionRequest(agent_id=agent, tool=tool, arguments={"n": n})


def h(n: int, agent: str = "a", tool: str = "send_email") -> str:
    return f"{abs(hash((n, agent, tool))):064x}"[:64]


def ask(store: ApprovalStore, n: int, agent: str = "a", tool: str = "send_email") -> str:
    approval_id = store.request(action(n, agent, tool), h(n, agent, tool))
    assert approval_id is not None
    return approval_id


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(clock: Clock) -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900, clock=clock)


def statuses(store: ApprovalStore, ids: list[str]) -> list[Status]:
    return [store._items[i].status for i in ids]


def test_approve_a_group_each_allows_exactly_once(store: ApprovalStore, clock: Clock) -> None:
    ids = [ask(store, n) for n in range(3)]
    clock.now += 600  # approving gives a fresh window
    decided = store.decide_group(ids, approve=True)
    assert [a.approval_id for a in decided] == ids
    assert statuses(store, ids) == [Status.APPROVED] * 3
    assert all(store._items[i].expires_at == clock.now + 900 for i in ids)
    for n, approval_id in enumerate(ids):
        assert store.use(approval_id, h(n), agent_id="a") is Status.APPROVED
        assert store.use(approval_id, h(n), agent_id="a") is Status.USED
        # Bound to its OWN action: another member's hash doesn't fit.
        assert store.use(approval_id, h((n + 1) % 3), agent_id="a") is None


def test_reject_a_group(store: ApprovalStore) -> None:
    ids = [ask(store, n) for n in range(3)]
    expires = [store._items[i].expires_at for i in ids]
    store.decide_group(ids, approve=False)
    assert statuses(store, ids) == [Status.DENIED] * 3
    assert [store._items[i].expires_at for i in ids] == expires
    assert store.use(ids[0], h(0), agent_id="a") is Status.DENIED


def test_an_approval_created_later_is_untouched(store: ApprovalStore) -> None:
    seen = [ask(store, n) for n in range(2)]
    later = ask(store, 9)
    store.decide_group(seen, approve=True)
    assert store._items[later].status is Status.PENDING


def refused(store: ApprovalStore, ids: list[str], approve: bool = True) -> dict[str, GroupReason]:
    store.pending()  # forget expired ones first (the decision does that too)
    before = {k: (a.status, a.expires_at) for k, a in store._items.items()}
    with pytest.raises(GroupDecideError) as caught:
        store.decide_group(ids, approve=approve)
    assert {k: (a.status, a.expires_at) for k, a in store._items.items()} == before
    return dict(caught.value.failed)


def test_unknown_id_refuses_the_whole_group(store: ApprovalStore) -> None:
    ids = [ask(store, n) for n in range(3)]
    assert refused(store, [*ids, "x" * 32]) == {"x" * 32: GroupReason.NOT_FOUND}


def test_expired_id_refuses_the_whole_group(store: ApprovalStore, clock: Clock) -> None:
    old = ask(store, 0)
    clock.now += 800
    new = [ask(store, n) for n in range(1, 3)]
    clock.now += 200  # `old` has expired, the others haven't
    assert refused(store, [old, *new]) == {old: GroupReason.NOT_FOUND}


@pytest.mark.parametrize("approve", [True, False])
def test_decided_used_or_revoked_refuses_the_whole_group(
    store: ApprovalStore, approve: bool
) -> None:
    ids = [ask(store, n) for n in range(5)]
    store.decide(ids[0], approve=True)  # approved, unused
    store.decide(ids[1], approve=True)
    assert store.use(ids[1], h(1), agent_id="a") is Status.APPROVED  # used
    store.decide(ids[2], approve=False)  # denied
    store.decide(ids[3], approve=True)
    store.decide(ids[3], approve=False)  # revoked
    failed = refused(store, ids, approve=approve)
    assert failed == {i: GroupReason.DECIDED for i in ids[:4]}
    assert store._items[ids[4]].status is Status.PENDING


def test_duplicate_id_refuses_the_whole_group(store: ApprovalStore) -> None:
    ids = [ask(store, n) for n in range(2)]
    assert refused(store, [ids[0], ids[1], ids[0]]) == {ids[0]: GroupReason.DUPLICATE}


def test_another_agent_refuses_the_whole_group(store: ApprovalStore) -> None:
    mine = [ask(store, n) for n in range(2)]
    theirs = ask(store, 0, agent="b")
    assert refused(store, [*mine, theirs]) == {theirs: GroupReason.MIXED}


def test_another_tool_refuses_the_whole_group(store: ApprovalStore) -> None:
    mine = [ask(store, n) for n in range(2)]
    other = ask(store, 0, tool="delete_file")
    assert refused(store, [other, *mine]) == {m: GroupReason.MIXED for m in mine}


def test_group_key_comes_from_the_first_known_id(store: ApprovalStore) -> None:
    mine = [ask(store, n) for n in range(2)]
    assert refused(store, ["u" * 32, *mine]) == {"u" * 32: GroupReason.NOT_FOUND}


@pytest.mark.parametrize("count", [0, MAX_GROUP + 1])
def test_group_size_limits(store: ApprovalStore, count: int) -> None:
    with pytest.raises(ValueError, match="1 to 100"):
        store.decide_group([f"{i:032d}" for i in range(count)], approve=True)


def test_max_group_size_works(clock: Clock) -> None:
    store = ApprovalStore(ttl_seconds=900, clock=clock, max_pending=MAX_GROUP)
    ids = [ask(store, n) for n in range(MAX_GROUP)]
    assert len(store.decide_group(ids, approve=True)) == MAX_GROUP


def test_failing_audit_changes_nothing(store: ApprovalStore) -> None:
    ids = [ask(store, n) for n in range(3)]
    seen: list[tuple[list[str], Status]] = []

    def audit(approvals: list[Approval], status: Status) -> None:
        seen.append(([a.approval_id for a in approvals], status))
        assert all(a.status is Status.PENDING for a in approvals)  # not changed yet
        raise OSError("disk full")

    with pytest.raises(OSError):
        store.decide_group(ids, approve=True, before_commit=audit)
    assert seen == [(ids, Status.APPROVED)]
    assert statuses(store, ids) == [Status.PENDING] * 3


def test_pending_groups_never_mix_and_are_ordered(store: ApprovalStore, clock: Clock) -> None:
    created = {}
    for n, (agent, tool) in enumerate(
        [("b", "x"), ("a", "y"), ("a", "x"), ("b", "x"), ("a", "x"), ("a", "x")]
    ):
        clock.now += 1 if n != 5 else 0  # the last two share a creation time
        created[ask(store, n, agent, tool)] = clock.now
    groups = store.pending_groups()
    assert [key for key, _ in groups] == [("a", "x"), ("a", "y"), ("b", "x")]
    for key, items in groups:
        assert all((a.agent_id, a.tool) == key for a, _ in items)
        order = [(created[a.approval_id], a.approval_id) for a, _ in items]
        assert order == sorted(order)
    assert sum(len(items) for _, items in groups) == 6


# --- Persistence -------------------------------------------------------------------------


def test_group_decision_is_persisted(tmp_path: Path) -> None:
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(db=db, ttl_seconds=900)
    ids = [ask(store, n) for n in range(3)]
    store.decide_group(ids, approve=True)
    again = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"), ttl_seconds=900)
    assert statuses(again, ids) == [Status.APPROVED] * 3
    assert again.use(ids[0], h(0), agent_id="a") is Status.APPROVED
    assert again.use(ids[0], h(0), agent_id="a") is Status.USED


def test_no_blind_group_approval_after_restart(tmp_path: Path) -> None:
    store = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"), ttl_seconds=900)
    ids = [ask(store, n) for n in range(3)]
    again = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"), ttl_seconds=900)
    ask(again, 1)  # the agent asked again for one: its arguments are back
    failed = refused(again, ids)
    assert failed == {ids[0]: GroupReason.NO_ARGUMENTS, ids[2]: GroupReason.NO_ARGUMENTS}
    again.decide_group(ids, approve=False)  # rejecting doesn't need the arguments
    assert statuses(again, ids) == [Status.DENIED] * 3


def test_failed_save_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(db=db, ttl_seconds=900)
    ids = [ask(store, n) for n in range(3)]

    def broken(approvals: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "save_many", broken)
    with pytest.raises(sqlite3.OperationalError):
        store.decide_group(ids, approve=True)
    assert statuses(store, ids) == [Status.PENDING] * 3


def test_save_many_is_one_transaction(tmp_path: Path) -> None:
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(db=db, ttl_seconds=900)
    ids = [ask(store, n) for n in range(2)]
    good = store._items[ids[0]]
    # SQLite can't store an object: the second row fails INSIDE the transaction.
    bad = Approval("b" * 32, object(), "t", None, "c" * 64, 1e12)  # type: ignore[arg-type]
    with pytest.raises(sqlite3.Error):
        db.save_many([Approval(**{**good.__dict__, "status": Status.APPROVED}), bad])
    reloaded = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"), ttl_seconds=900)
    assert reloaded._items[ids[0]].status is Status.PENDING


def test_old_database_gets_created_at(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE approvals (approval_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, "
            "tool TEXT NOT NULL, action_hash TEXT NOT NULL, status TEXT NOT NULL, "
            "expires_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO approvals VALUES (?, 'a', 't', ?, 'pending', 9e9)", ("o" * 32, "d" * 64)
        )
    path.chmod(0o600)
    store = ApprovalStore(db=ApprovalDB(path), ttl_seconds=900)
    assert store._items["o" * 32].created_at == 9e9 - 900
    ask(store, 1)  # new rows save created_at
    reloaded = ApprovalStore(db=ApprovalDB(path), ttl_seconds=900)
    assert all(a.created_at for a in reloaded._items.values())


# --- Races -------------------------------------------------------------------------------


@pytest.mark.parametrize("attempt", range(20))
def test_group_decision_races_single_decisions_and_uses(attempt: int) -> None:
    """Many threads: groups, single approves/denies and uses on the same ids. Each
    approval is decided once, and gives at most one allow."""
    store = ApprovalStore(ttl_seconds=900)
    ids = [ask(store, n) for n in range(6)]
    grants: list[str] = []
    outcomes: list[str] = []
    barrier = threading.Barrier(8)

    def group(approve: bool) -> None:
        barrier.wait()
        try:
            store.decide_group(ids, approve=approve)
            outcomes.append("group-" + str(approve))
        except GroupDecideError:
            pass

    def single(i: int) -> None:
        barrier.wait()
        try:
            store.decide(ids[i], approve=False)
            outcomes.append(f"single-{i}")
        except Exception:  # noqa: S110 (decided already: fine)
            pass

    def use(i: int) -> None:
        barrier.wait()
        for _ in range(50):
            if store.use(ids[i], h(i), agent_id="a") is Status.APPROVED:
                grants.append(ids[i])

    threads = [
        threading.Thread(target=group, args=(True,)),
        threading.Thread(target=group, args=(False,)),
        threading.Thread(target=single, args=(2,)),
        threading.Thread(target=single, args=(4,)),
        *[threading.Thread(target=use, args=(i,)) for i in (0, 2, 4, 5)],
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(grants) == len(set(grants))  # never twice
    groups = [o for o in outcomes if o.startswith("group")]
    assert len(groups) <= 1  # the second group always finds something decided
    if groups != ["group-True"]:
        assert not grants  # nothing was ever approved
