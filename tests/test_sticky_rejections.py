"""Sticky rejections: after a human says no, the same agent asking for the same action
is refused for the rejection window instead of nagging with a new pending approval.
See docs/design/sticky-rejections.md."""

import io
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server, shown
from pydantic import ValidationError

from warden.api import create_app
from warden.approvals import (
    ApprovalDB,
    ApprovalStore,
    DecideError,
    PendingQuotaExceeded,
    Rejected,
    Status,
    apply_approval,
)
from warden.audit import AuditEvent, EventKind, SQLiteAuditLog
from warden.cli import main
from warden.limits import DEFAULT_REJECTION_WINDOW_SECONDS, Limits
from warden.models import ActionRequest, Decision, EvaluationResult

KEY = "sticky-admin-key-0123456789abcdef"
ADMIN = {"X-Warden-Admin-Key": KEY}
MARKER = "STICKYMARKER-123"  # must never appear in answers or listings


def act(n: int = 0, agent: str = "a") -> ActionRequest:
    return ActionRequest(agent_id=agent, tool="t", arguments={"n": n, "s": MARKER})


def h(n: int = 0, agent: str = "a") -> str:
    return f"{agent}{n}".ljust(64, "0")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# --- The store ---------------------------------------------------------------------------


def make(window: float = 900, **kwargs: Any) -> tuple[ApprovalStore, Clock]:
    clock = Clock()
    store = ApprovalStore(ttl_seconds=900, clock=clock, rejection_window=lambda a: window, **kwargs)
    return store, clock


def test_rejected_action_stays_rejected_for_the_window() -> None:
    store, clock = make(window=600)
    approval_id = store.request(act(), h())
    assert approval_id is not None
    clock.now += 500  # most of the original TTL is gone: the window starts at the "no"
    store.decide(approval_id, approve=False)
    clock.now += 599
    with pytest.raises(Rejected) as caught:
        store.request(act(), h())
    assert caught.value.approval_id == approval_id
    assert caught.value.seconds_left == pytest.approx(1)
    clock.now += 1  # the window is over: asking again is an ordinary pending approval
    again = store.request(act(), h())
    assert again is not None and again != approval_id


def test_only_the_exact_action_is_refused() -> None:
    store, _ = make()
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=False)
    assert store.request(act(1), h(1)) is not None  # different arguments
    assert store.request(act(0, "b"), h(0, "b")) is not None  # different agent


def test_revoking_an_approval_is_sticky_too() -> None:
    store, clock = make()
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=True)
    store.decide(approval_id, approve=False)  # revoke
    clock.now += 899
    with pytest.raises(Rejected):
        store.request(act(), h())
    assert store.use(approval_id, h()) is Status.DENIED


def test_window_zero_keeps_the_old_behaviour() -> None:
    store, clock = make(window=0)
    approval_id = store.request(act(), h())
    assert approval_id is not None
    clock.now += 100
    store.decide(approval_id, approve=False)
    again = store.request(act(), h())  # not refused: a new pending approval
    assert again is not None and again != approval_id
    assert store.rejections() == []
    clock.now += 800  # the denied row keeps the rest of its original TTL, as before
    assert store.use(approval_id, h()) is None


def test_window_is_per_agent() -> None:
    clock = Clock()
    store = ApprovalStore(clock=clock, rejection_window=lambda agent: 0 if agent == "free" else 900)
    for agent in ("free", "strict"):
        approval_id = store.request(act(0, agent), h(0, agent))
        assert approval_id is not None
        store.decide(approval_id, approve=False)
    assert store.request(act(0, "free"), h(0, "free")) is not None
    with pytest.raises(Rejected):
        store.request(act(0, "strict"), h(0, "strict"))


def test_default_window_without_a_policy() -> None:
    store = ApprovalStore()
    assert store.rejection_window("anyone") == DEFAULT_REJECTION_WINDOW_SECONDS


def test_rejections_do_not_count_toward_the_pending_quota() -> None:
    store, _ = make()
    approval_id = store.request(act(), h(), agent_limit=1)
    assert approval_id is not None
    store.decide(approval_id, approve=False)
    assert store.request(act(1), h(1), agent_limit=1) is not None
    with pytest.raises(PendingQuotaExceeded):
        store.request(act(2), h(2), agent_limit=1)


def test_a_rejection_beats_the_quota_and_the_global_limit() -> None:
    store, _ = make(max_pending=1)
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=False)
    assert store.request(act(1), h(1)) is not None  # the one pending slot
    with pytest.raises(Rejected):
        store.request(act(), h(), agent_limit=0)


def test_group_reject_makes_each_sticky() -> None:
    store, clock = make()
    ids = [store.request(act(n), h(n)) for n in range(3)]
    assert all(ids)
    store.decide_group([i for i in ids if i], approve=False)
    clock.now += 899
    for n in range(3):
        with pytest.raises(Rejected) as caught:
            store.request(act(n), h(n))
        assert caught.value.approval_id == ids[n]
    assert [a.approval_id for a, _, _ in store.rejections()] == ids


def test_group_approve_is_not_sticky() -> None:
    store, _ = make()
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide_group([approval_id], approve=True)
    assert store.request(act(), h()) == approval_id  # the approved one is reused
    assert store.rejections() == []


def test_rejections_list_shows_time_left_and_since() -> None:
    store, clock = make(window=600)
    first = store.request(act(), h())
    second = store.request(act(1), h(1))
    assert first and second
    store.decide(first, approve=False)
    clock.now += 100
    store.decide(second, approve=False)
    clock.now += 50
    listed = [(a.approval_id, left, since) for a, left, since in store.rejections()]
    assert listed == [(first, 450, 150), (second, 550, 50)]
    clock.now += 450  # the first one ends
    assert [a.approval_id for a, _, _ in store.rejections()] == [second]


def test_lift_lets_the_agent_ask_again() -> None:
    store, _ = make()
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=False)
    seen: list[str] = []
    store.lift(approval_id, before_commit=lambda a: seen.append(a.approval_id))
    assert seen == [approval_id]
    again = store.request(act(), h())
    assert again is not None and again != approval_id
    # The new request is pending: a human must still approve it after seeing it.
    assert [a.approval_id for a, _ in store.pending()] == [again]
    assert store.use(approval_id, h()) is None  # the lifted id is gone


def test_lift_refuses_unknown_and_non_rejections() -> None:
    store, clock = make()
    with pytest.raises(DecideError) as caught:
        store.lift("nope")
    assert caught.value.not_found
    approval_id = store.request(act(), h())
    assert approval_id is not None
    with pytest.raises(DecideError) as caught:
        store.lift(approval_id)  # pending, not a rejection
    assert not caught.value.not_found
    store.decide(approval_id, approve=True)
    with pytest.raises(DecideError):
        store.lift(approval_id)  # approved, not a rejection
    store.decide(approval_id, approve=False)
    clock.now += 900  # expired
    with pytest.raises(DecideError) as caught:
        store.lift(approval_id)
    assert caught.value.not_found


def test_lift_does_nothing_if_the_audit_fails() -> None:
    store, _ = make()
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=False)

    def broken(_: Any) -> None:
        raise sqlite3.OperationalError("disk full")

    with pytest.raises(sqlite3.OperationalError):
        store.lift(approval_id, before_commit=broken)
    with pytest.raises(Rejected):
        store.request(act(), h())


def test_rejection_survives_a_restart(tmp_path: Path) -> None:
    clock = Clock()
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(clock=clock, db=db)
    approval_id = store.request(act(), h())
    assert approval_id is not None
    clock.now += 800
    store.decide(approval_id, approve=False)
    clock.now += 800  # past the original TTL, inside the rejection window
    restarted = ApprovalStore(clock=clock, db=ApprovalDB(tmp_path / "a.db"))
    with pytest.raises(Rejected):
        restarted.request(act(), h())
    [(approval, left, since)] = restarted.rejections()
    assert (approval.approval_id, left, since) == (approval_id, 100, 800)
    restarted.lift(approval_id)
    after_lift = ApprovalStore(clock=clock, db=ApprovalDB(tmp_path / "a.db"))
    assert after_lift.rejections() == []
    assert after_lift.request(act(), h()) not in {None, approval_id}


def test_lift_does_nothing_if_the_database_fails(tmp_path: Path) -> None:
    clock = Clock()
    db = ApprovalDB(tmp_path / "a.db")
    store = ApprovalStore(clock=clock, db=db)
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=False)

    def broken(ids: list[str]) -> None:
        raise sqlite3.OperationalError("disk full")

    db.delete = broken  # type: ignore[method-assign,assignment]
    with pytest.raises(sqlite3.OperationalError):
        store.lift(approval_id)
    with pytest.raises(Rejected):
        store.request(act(), h())


def test_old_database_gets_the_decided_at_column(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE approvals (approval_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, "
            "tool TEXT NOT NULL, action_hash TEXT NOT NULL, status TEXT NOT NULL, "
            "expires_at REAL NOT NULL, created_at REAL)"
        )
        conn.execute("INSERT INTO approvals VALUES ('x', 'a', 't', ?, 'denied', 2000, 1)", (h(),))
    conn.close()
    store = ApprovalStore(clock=Clock(), db=ApprovalDB(path))
    with pytest.raises(Rejected):  # an old denied row still refuses (safer side)
        store.request(act(), h())
    [(_, left, since)] = store.rejections()
    assert (left, since) == (1000, 0)  # rejection time unknown: shown as "now"


def test_apply_approval_turns_a_rejection_into_deny_without_arguments() -> None:
    store, _ = make()
    approval_id = store.request(act(), h())
    assert approval_id is not None
    store.decide(approval_id, approve=False)
    engine = EvaluationResult(
        decision=Decision.REQUIRE_APPROVAL,
        reason="needs approval",
        matched_rule="r",
        action_hash=h(),
    )
    result = apply_approval(act(), engine, store)
    assert result.decision is Decision.DENY
    assert result.reason.startswith("rejected by a human; this exact action is refused until ")
    assert result.reason.endswith(f" UTC (approval {approval_id})")
    assert MARKER not in result.model_dump_json()
    assert (result.matched_rule, result.action_hash, result.approval_id) == ("r", h(), None)


# --- Limits ------------------------------------------------------------------------------


def test_limits_rejection_window() -> None:
    assert Limits().rejection_window_seconds("x") == 900
    limits = Limits.model_validate(
        {
            "default": {"rejection_window_seconds": 60},
            "agents": {"off": {"rejection_window_seconds": 0}, "other": {}},
        }
    )
    assert limits.rejection_window_seconds("off") == 0
    assert limits.rejection_window_seconds("other") == 60
    assert limits.rejection_window_seconds("unknown") == 60
    week = 7 * 24 * 3600
    assert Limits.model_validate({"default": {"rejection_window_seconds": week}})
    for bad in (-1, week + 1, 1.5, "900", True):
        with pytest.raises(ValidationError):
            Limits.model_validate({"default": {"rejection_window_seconds": bad}})


# --- The HTTP API ------------------------------------------------------------------------

EMAIL = {"agent_id": "agent-1", "tool": "send_email", "arguments": {"to": MARKER + "@x.com"}}


def policy_file(tmp_path: Path, limits: dict[str, Any] | None) -> Path:
    data = json.loads(BASIC_POLICY.read_text())
    if limits is not None:
        data["limits"] = limits
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def app_with(
    tmp_path: Path, limits: dict[str, Any] | None = None, log: SQLiteAuditLog | None = None
) -> tuple[TestClient, SQLiteAuditLog, ApprovalStore]:
    log = log or SQLiteAuditLog(tmp_path / "audit.db")
    store = ApprovalStore()
    app = create_app(policy_file(tmp_path, limits), audit_log=log, approvals=store, admin_key=KEY)
    app.state.warden.record_in_background = False
    return TestClient(app), log, store


def reject_one(client: TestClient) -> str:
    approval_id: str = client.post("/v1/evaluate", json=EMAIL).json()["approval_id"]
    assert (
        client.post(
            f"/v1/approvals/{approval_id}/deny",
            headers=ADMIN,
            json=shown(client, approval_id, ADMIN),
        ).status_code
        == 200
    )
    return approval_id


def test_api_asking_again_after_a_rejection_is_denied(tmp_path: Path) -> None:
    client, log, _ = app_with(tmp_path)
    approval_id = reject_one(client)
    response = client.post("/v1/evaluate", json=EMAIL)
    body = response.json()
    assert response.status_code == 200
    assert body["decision"] == "deny"
    assert body["reason"].startswith("rejected by a human; this exact action is refused until")
    assert approval_id in body["reason"]
    assert body["approval_id"] is None
    assert MARKER not in response.text
    entry = log.recent(1)[0]
    assert (entry.decision, entry.reason) == (Decision.DENY, body["reason"])
    assert client.get("/v1/approvals", headers=ADMIN).json() == []  # no new pending one


def test_api_lists_standing_rejections_without_arguments(tmp_path: Path) -> None:
    client, _, _ = app_with(tmp_path)
    approval_id = reject_one(client)
    other = {**EMAIL, "agent_id": "agent-2"}
    other_id = client.post("/v1/evaluate", json=other).json()["approval_id"]
    response = client.get("/v1/approvals?status=rejected", headers=ADMIN)
    [item] = response.json()
    assert item["approval_id"] == approval_id
    assert (item["agent_id"], item["tool"]) == ("agent-1", "send_email")
    assert len(item["action_hash"]) == 64
    assert 899 <= item["expires_in_seconds"] <= 900
    assert item["rejected_at"].endswith("Z")
    assert "arguments" not in item and MARKER not in response.text
    # The filters narrow the view, as for pending approvals.
    path = "/v1/approvals?status=rejected&agent_id=agent-2"
    assert client.get(path, headers=ADMIN).json() == []
    assert client.get(f"/v1/approvals?status=rejected&ids={other_id}", headers=ADMIN).json() == []
    # Pending listing is unchanged and is the default.
    pending = client.get("/v1/approvals?status=pending", headers=ADMIN).json()
    assert [p["approval_id"] for p in pending] == [other_id]


def test_api_rejected_listing_refuses_group_and_bad_status(tmp_path: Path) -> None:
    client, _, _ = app_with(tmp_path)
    grouped = client.get("/v1/approvals?status=rejected&group=true", headers=ADMIN)
    assert grouped.status_code == 422 and grouped.json()["decision"] == "deny"
    assert client.get("/v1/approvals?status=used", headers=ADMIN).status_code == 422
    assert client.get("/v1/approvals?status=rejected").status_code == 401


def test_api_lift_is_audited_and_lets_the_agent_ask_again(tmp_path: Path) -> None:
    client, log, _ = app_with(tmp_path)
    approval_id = reject_one(client)
    response = client.post(f"/v1/approvals/{approval_id}/lift", headers=ADMIN)
    assert response.json() == {"approval_id": approval_id, "status": "lifted"}
    event = log.recent_events()[0]
    assert (event.kind, event.reason) == (
        EventKind.APPROVAL_REJECTION_LIFTED,
        "rejection lifted by admin",
    )
    assert (event.approval_id, event.agent_id, event.tool) == (
        approval_id,
        "agent-1",
        "send_email",
    )
    again = client.post("/v1/evaluate", json=EMAIL).json()
    assert again["decision"] == "require_approval"
    assert again["approval_id"] not in (None, approval_id)
    assert client.get("/v1/approvals?status=rejected", headers=ADMIN).json() == []


def test_api_lift_refusals(tmp_path: Path) -> None:
    client, log, _ = app_with(tmp_path)
    assert client.post("/v1/approvals/x/lift").status_code == 401
    unknown = client.post("/v1/approvals/nope/lift", headers=ADMIN)
    assert (unknown.status_code, unknown.json()) == (404, {"error": "rejection not found"})
    pending_id = client.post("/v1/evaluate", json=EMAIL).json()["approval_id"]
    not_one = client.post(f"/v1/approvals/{pending_id}/lift", headers=ADMIN)
    assert not_one.status_code == 409
    assert not_one.json() == {"error": "not a rejection (nothing to lift)"}
    event = log.recent_events()[0]
    assert (event.kind, event.http_status, event.approval_id) == (
        EventKind.APPROVAL_DECIDE_FAILED,
        409,
        pending_id,
    )
    long_id = "y" * 500  # not an approval id: not kept in the log
    client.post(f"/v1/approvals/{long_id}/lift", headers=ADMIN)
    assert log.recent_events()[0].approval_id is None


class EventsBroken(SQLiteAuditLog):
    def record_event(self, event: AuditEvent) -> None:
        if event.kind is EventKind.APPROVAL_REJECTION_LIFTED:
            raise sqlite3.OperationalError("disk full")
        super().record_event(event)


def test_api_lift_does_not_happen_if_the_audit_fails(tmp_path: Path) -> None:
    client, _, _ = app_with(tmp_path, log=EventsBroken(tmp_path / "audit.db"))
    approval_id = reject_one(client)
    response = client.post(f"/v1/approvals/{approval_id}/lift", headers=ADMIN)
    assert (response.status_code, response.json()) == (
        503,
        {"error": "audit log unavailable, nothing changed"},
    )
    assert client.post("/v1/evaluate", json=EMAIL).json()["decision"] == "deny"


def test_api_lift_storage_failure_is_logged_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, log, store = app_with(tmp_path)
    approval_id = reject_one(client)
    original = store.lift

    def lift_then_fail(approval_id: str, before_commit: Any) -> None:
        def audit_then_fail(approval: Any) -> None:
            before_commit(approval)
            raise sqlite3.OperationalError("disk full")

        original(approval_id, before_commit=audit_then_fail)

    monkeypatch.setattr(store, "lift", lift_then_fail)
    assert client.post(f"/v1/approvals/{approval_id}/lift", headers=ADMIN).status_code == 503
    latest, lifted = log.recent_events()[:2]
    assert lifted.kind is EventKind.APPROVAL_REJECTION_LIFTED
    assert latest.kind is EventKind.APPROVAL_DECIDE_FAILED
    assert latest.reason == "lift NOT applied (approval storage failed), the rejection stands"
    assert latest.approval_id == approval_id
    assert client.post("/v1/evaluate", json=EMAIL).json()["decision"] == "deny"


def test_api_policy_window_zero_turns_it_off(tmp_path: Path) -> None:
    client, _, _ = app_with(tmp_path, {"default": {"rejection_window_seconds": 0}})
    approval_id = reject_one(client)
    again = client.post("/v1/evaluate", json=EMAIL).json()
    assert again["decision"] == "require_approval" and again["approval_id"] != approval_id


def test_api_group_reject_is_sticky(tmp_path: Path) -> None:
    client, _, _ = app_with(tmp_path)
    bodies = [{**EMAIL, "arguments": {"to": f"p{i}@x.com"}} for i in range(2)]
    ids = [client.post("/v1/evaluate", json=b).json()["approval_id"] for b in bodies]
    hashes = [shown(client, i, ADMIN)["action_hash"] for i in ids]
    decision = {"ids": ids, "action_hashes": hashes, "approve": False}
    decided = client.post("/v1/approvals/decide", headers=ADMIN, json=decision)
    assert decided.status_code == 200
    for body in bodies:
        assert client.post("/v1/evaluate", json=body).json()["decision"] == "deny"


# --- The CLI -----------------------------------------------------------------------------


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, TestClient]]:
    app = create_app(
        BASIC_POLICY,
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        approvals=ApprovalStore(),
        admin_key=KEY,
    )
    with live_server(app) as url:
        yield url, TestClient(app)


def cli(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    *argv: str,
    answer: str = "",
) -> tuple[int, str, str]:
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    monkeypatch.delenv("WARDEN_URL", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(answer))
    code = main(["approvals", *argv])
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err
    return code, captured.out, captured.err


def test_cli_list_rejected_and_lift(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    code, out, _ = cli(capsys, monkeypatch, "list", "--rejected", "--warden-url", url)
    assert (code, out) == (0, "No standing rejections.\n")
    approval_id = reject_one(client)
    code, out, _ = cli(capsys, monkeypatch, "list", "--rejected", "--warden-url", url)
    assert code == 0 and approval_id in out and "agent agent-1, tool send_email" in out
    assert MARKER not in out
    code, out, _ = cli(
        capsys, monkeypatch, "list", "--rejected", "--agent", "other", "--warden-url", url
    )
    assert out == "No standing rejections.\n"
    # Asked, answered no: nothing changes.
    code, out, _ = cli(capsys, monkeypatch, "lift", approval_id, "--warden-url", url, answer="n")
    assert code == 1 and "Lift this rejection?" in out and "Nothing changed." in out
    assert client.post("/v1/evaluate", json=EMAIL).json()["decision"] == "deny"
    code, out, _ = cli(capsys, monkeypatch, "lift", approval_id, "--warden-url", url, answer="y")
    assert code == 0 and "Lifted." in out
    assert client.post("/v1/evaluate", json=EMAIL).json()["decision"] == "require_approval"


def test_cli_lift_refusals(server: tuple[str, TestClient], capsys: Any, monkeypatch: Any) -> None:
    url, client = server
    pending_id = client.post("/v1/evaluate", json=EMAIL).json()["approval_id"]
    code, _, err = cli(capsys, monkeypatch, "lift", pending_id, "--yes", "--warden-url", url)
    assert code == 1 and "not a standing rejection" in err
    code, _, err = cli(capsys, monkeypatch, "lift", "--warden-url", url)
    assert code == 2 and "needs at least one approval id" in err
    code, _, err = cli(capsys, monkeypatch, "lift", "a" * 32, "b" * 32, "--warden-url", url)
    assert code == 2 and "takes one id" in err
    code, _, err = cli(
        capsys, monkeypatch, "approve", pending_id, "--rejected", "--warden-url", url
    )
    assert code == 2 and "--rejected is for `list`" in err
    code, _, err = cli(capsys, monkeypatch, "list", "--rejected", "--group", "--warden-url", url)
    assert code == 2
    monkeypatch.setenv("WARDEN_ADMIN_KEY", "wrong")
    code = main(["approvals", "list", "--rejected", "--warden-url", url])
    assert code == 1


def test_cli_lift_reports_a_server_refusal(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    approval_id = reject_one(client)
    store = client.app.state.warden.approvals  # type: ignore[attr-defined]

    def gone(approval_id: str, before_commit: Any) -> None:
        raise DecideError(not_found=True)  # lifted by someone else in between

    monkeypatch.setattr(store, "lift", gone)
    code, _, err = cli(capsys, monkeypatch, "lift", approval_id, "--yes", "--warden-url", url)
    assert code == 1 and "rejection not found" in err


def test_cli_lift_with_a_wrong_key_at_the_lift_step(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    approval_id = reject_one(client)
    calls: list[str] = []
    from warden import approvals_cli

    real = approvals_cli._call

    def fake(url: str, key: str, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        calls.append(method)
        if method == "POST":
            return 401, {"error": "admin key missing or wrong"}
        return real(url, key, method, path, body)

    monkeypatch.setattr(approvals_cli, "_call", fake)
    code, _, err = cli(capsys, monkeypatch, "lift", approval_id, "--yes", "--warden-url", url)
    assert code == 1 and "WARDEN_ADMIN_KEY is wrong" in err and calls == ["GET", "POST"]


def test_cli_rejected_listing_with_an_unexpected_answer(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, _ = server
    from warden import approvals_cli

    monkeypatch.setattr(approvals_cli, "_call", lambda *a, **k: (200, [1]))
    code, _, err = cli(capsys, monkeypatch, "list", "--rejected", "--warden-url", url)
    assert code == 2 and "unexpected answer" in err
    monkeypatch.setattr(approvals_cli, "_call", lambda *a, **k: (500, {}))
    code, _, err = cli(capsys, monkeypatch, "list", "--rejected", "--warden-url", url)
    assert code == 2 and "HTTP 500" in err
