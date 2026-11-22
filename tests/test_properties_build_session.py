"""Property tests for rate limits, the audit hash chain and approvals: random sequences
of operations, invariants that must always hold."""

import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from warden.approvals import ApprovalStore, DecideError, Status
from warden.audit import AuditEntry, AuditEvent, EventKind, SQLiteAuditLog, verify_chain
from warden.limits import Limits, RateLimiter
from warden.models import ActionRequest, Decision

# --- Rate limiter ---------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(
    rpm=st.integers(1, 120),
    steps=st.lists(st.tuples(st.floats(0, 30), st.integers(1, 5)), min_size=1, max_size=40),
)
def test_never_more_than_burst_plus_refill(rpm: int, steps: list[tuple[float, int]]) -> None:
    """Over any run: allowed <= capacity + elapsed * rate. And a wait it announces is
    enough: asking again after it is allowed (if nobody else used the bucket)."""
    now = [0.0]
    limiter = RateLimiter(
        Limits.model_validate({"default": {"requests_per_minute": rpm}}), clock=lambda: now[0]
    )
    allowed = 0
    for gap, burst in steps:
        now[0] += gap
        for _ in range(burst):
            wait = limiter.acquire("a")
            if wait == 0:
                allowed += 1
            else:
                assert 0 < wait <= 60.0 / rpm + 1e-9
    assert allowed <= rpm + now[0] * rpm / 60.0 + 1e-6
    wait = limiter.acquire("a")
    if wait:
        now[0] += wait + 1e-6
        assert limiter.acquire("a") == 0


# --- Audit chain ----------------------------------------------------------------------

START = datetime(2026, 6, 1, tzinfo=UTC)
operations = st.lists(
    st.one_of(
        st.tuples(st.just("decision"), st.integers(0, 200)),
        st.tuples(st.just("event"), st.integers(0, 200)),
        st.tuples(st.just("purge"), st.integers(1, 150)),
    ),
    min_size=1,
    max_size=25,
)


def build(ops: list[tuple[str, int]], path: Path) -> SQLiteAuditLog:
    log = SQLiteAuditLog(path, retention_days=None, clock=lambda: START)
    for kind, n in ops:
        when = (START - timedelta(days=n)).isoformat()
        if kind == "decision":
            log.record(
                AuditEntry(
                    timestamp=when,
                    agent_id="a",
                    tool="t",
                    decision=Decision.ALLOW,
                    reason="r",
                    matched_rule=None,
                    action_hash=None,
                )
            )
        elif kind == "event":
            log.record_event(
                AuditEvent(timestamp=when, kind=EventKind.REQUEST_REJECTED, reason="x")
            )
        else:
            log.purge_older_than(n)
    return log


@settings(max_examples=150, deadline=None)
@given(operations)
def test_any_mix_of_writes_and_purges_verifies(ops: list[tuple[str, int]]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.db"
        build(ops, path)
        report = verify_chain(path)
        assert report.ok, report.problems


@settings(max_examples=150, deadline=None)
@given(operations, st.integers(0, 10_000), st.sampled_from(["reason", "agent_id", "delete"]))
def test_any_single_edit_in_the_middle_is_found(
    ops: list[tuple[str, int]], pick: int, how: str
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "a.db"
        build(ops, path)
        with sqlite3.connect(path) as conn:
            ids = [r[0] for r in conn.execute("SELECT id FROM decisions ORDER BY id")]
            if len(ids) < 2:
                return
            # Not the newest row: cutting the tail is only visible with a saved head.
            target = ids[pick % (len(ids) - 1)]
            if how == "delete":
                conn.execute("DELETE FROM decisions WHERE id = ?", (target,))
            else:
                conn.execute(f"UPDATE decisions SET {how} = 'forged' WHERE id = ?", (target,))  # noqa: S608
        assert not verify_chain(path).ok


# --- Approvals: random operations, one allow at most per approval ---------------------

approval_ops = st.lists(
    st.tuples(
        st.sampled_from(["request", "approve", "deny", "use", "use-other", "tick"]),
        st.integers(0, 2),
    ),
    max_size=40,
)


@settings(max_examples=400, deadline=None)
@given(approval_ops)
def test_each_approval_grants_at_most_one_allow_per_approval(ops: list[tuple[str, int]]) -> None:
    now = [0.0]
    store = ApprovalStore(ttl_seconds=100, clock=lambda: now[0])
    actions = [ActionRequest(agent_id="a", tool="t", arguments={"n": i}) for i in range(3)]
    hashes = [f"{i:064x}" for i in range(3)]
    ids: dict[int, str] = {}
    grants: dict[str, int] = {}
    for op, i in ops:
        if op == "request":
            approval_id = store.request(actions[i], hashes[i])
            assert approval_id is not None
            ids[i] = approval_id
        elif op == "tick":
            now[0] += 60
        elif i in ids:
            approval_id = ids[i]
            if op in {"approve", "deny"}:
                try:
                    store.decide(approval_id, approve=op == "approve")
                except DecideError:
                    pass  # not found / already decided: fine
            elif op == "use":
                if store.use(approval_id, hashes[i], agent_id="a") is Status.APPROVED:
                    grants[approval_id] = grants.get(approval_id, 0) + 1
            elif op == "use-other":  # wrong action or wrong agent: never granted
                assert store.use(approval_id, hashes[(i + 1) % 3], agent_id="a") is None
                assert store.use(approval_id, hashes[i], agent_id="b") is None
    # Each approval id was granted at most once.
    assert all(count == 1 for count in grants.values())
