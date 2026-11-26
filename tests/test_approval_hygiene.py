"""Approval hygiene: the default list shows only pending, unexpired approvals, each with
its age; `--max-age` narrows it; the CLI warns about (and with --yes refuses) approving
actions from separate agent runs. See docs/design/approval-hygiene.md."""

import io
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, Clock, live_server

from warden.api import create_app
from warden.approvals import ApprovalStore, Status
from warden.approvals_cli import RUN_GAP_SECONDS, _runs
from warden.audit import SQLiteAuditLog
from warden.cli import main

KEY = "hygiene-admin-key-0123456789abcdef"
ADMIN = {"X-Warden-Admin-Key": KEY}


@pytest.fixture
def clock() -> Clock[float]:
    return Clock(1000.0)


@pytest.fixture
def store(clock: Clock[float]) -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900, clock=clock)


@pytest.fixture
def app(tmp_path: Path, store: ApprovalStore) -> Any:
    return create_app(
        BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), approvals=store, admin_key=KEY
    )


@pytest.fixture
def client(app: Any) -> TestClient:
    return TestClient(app)


def email(n: int, agent: str = "agent-1") -> dict[str, Any]:
    return {"agent_id": agent, "tool": "send_email", "arguments": {"to": f"p{n}@example.com"}}


def ask(client: TestClient, n: int, agent: str = "agent-1") -> str:
    approval_id: str = client.post("/v1/evaluate", json=email(n, agent)).json()["approval_id"]
    return approval_id


def listed(client: TestClient, query: str = "") -> list[str]:
    return [i["approval_id"] for i in client.get("/v1/approvals" + query, headers=ADMIN).json()]


def grouped(client: TestClient) -> list[str]:
    groups = client.get("/v1/approvals?group=true", headers=ADMIN).json()["groups"]
    return [a["approval_id"] for g in groups for a in g["approvals"]]


def hash_of(store: ApprovalStore, approval_id: str) -> str:
    return store._items[approval_id].action_hash


# --- The default view: pending and unexpired only (a tested promise) ---------------------


def test_default_list_shows_only_pending_unexpired(
    client: TestClient, store: ApprovalStore, clock: Clock[float]
) -> None:
    old = ask(client, 0)
    clock.now += 600
    approved, rejected, used, pending = (ask(client, n) for n in range(1, 5))
    for approval_id, approve in [(approved, True), (rejected, False), (used, True)]:
        body = {"action_hash": hash_of(store, approval_id)}
        verb = "approve" if approve else "deny"
        r = client.post(f"/v1/approvals/{approval_id}/{verb}", headers=ADMIN, json=body)
        assert r.status_code == 200
    ran = client.post("/v1/evaluate", json={**email(3), "approval_id": used}).json()
    assert ran["decision"] == "allow"
    assert store._items[used].status is Status.USED
    clock.now += 301  # `old` (asked 901 s ago) has expired; the others haven't
    for view in (listed(client), listed(client, "?status=pending"), grouped(client)):
        assert view == [pending]
    assert old not in store._items  # expired: forgotten, so it can't be decided either


def test_expired_pending_approvals_disappear_from_every_view(
    client: TestClient, clock: Clock[float]
) -> None:
    approval_id = ask(client, 0)
    clock.now += 899
    assert listed(client) == [approval_id] == grouped(client)
    clock.now += 1
    assert listed(client) == [] == grouped(client)


# --- age_seconds and max_age_seconds -------------------------------------------------------


def test_each_item_shows_its_age(client: TestClient, clock: Clock[float]) -> None:
    first = ask(client, 0)
    clock.now += 130.7
    second = ask(client, 1)
    items = {i["approval_id"]: i for i in client.get("/v1/approvals", headers=ADMIN).json()}
    assert items[first]["age_seconds"] == 130
    assert items[second]["age_seconds"] == 0
    assert items[first]["expires_in_seconds"] == 769
    groups = client.get("/v1/approvals?group=true", headers=ADMIN).json()["groups"]
    assert [a["age_seconds"] for a in groups[0]["approvals"]] == [130, 0]


def test_max_age_narrows_the_view(client: TestClient, clock: Clock[float]) -> None:
    old = ask(client, 0)
    clock.now += 300
    new = ask(client, 1)
    clock.now += 60
    assert listed(client, "?max_age_seconds=60") == [new]
    assert listed(client, "?max_age_seconds=59") == []
    assert sorted(listed(client, "?max_age_seconds=360")) == sorted([old, new])
    groups = client.get("/v1/approvals?group=true&max_age_seconds=60", headers=ADMIN).json()
    assert [a["approval_id"] for g in groups["groups"] for a in g["approvals"]] == [new]
    assert client.get("/v1/approvals?group=true&max_age_seconds=1", headers=ADMIN).json() == {
        "groups": []
    }


@pytest.mark.parametrize("value", ["0", "-1", "604801", "abc", "1.5"])
def test_max_age_out_of_range_is_refused(client: TestClient, value: str) -> None:
    r = client.get(f"/v1/approvals?max_age_seconds={value}", headers=ADMIN)
    assert r.status_code == 422
    assert "decision" in r.json() and r.json()["decision"] == "deny"


def test_max_age_is_not_for_rejections(client: TestClient) -> None:
    r = client.get("/v1/approvals?status=rejected&max_age_seconds=60", headers=ADMIN)
    assert r.status_code == 422
    assert "max_age_seconds is only for pending approvals" in r.text


def test_max_age_needs_the_admin_key(client: TestClient) -> None:
    assert client.get("/v1/approvals?max_age_seconds=60").status_code == 401


# --- The CLI -----------------------------------------------------------------------------


@pytest.fixture
def server(app: Any) -> Iterator[str]:
    with live_server(app) as url:
        yield url


@pytest.fixture(autouse=True)
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    monkeypatch.delenv("WARDEN_URL", raising=False)


def cli(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    *argv: str,
    answer: str = "",
) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(answer))
    code = main(["approvals", argv[0], "--warden-url", url, *argv[1:]])
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err
    return code, captured.out, captured.err


def test_cli_list_shows_age(
    server: str, client: TestClient, clock: Clock[float], capsys: Any, monkeypatch: Any
) -> None:
    ask(client, 0)
    clock.now += 480
    ask(client, 1)
    clock.now += 5
    code, out, _ = cli(capsys, monkeypatch, server, "list")
    assert code == 0
    assert "asked 8 min ago, expires in 415s" in out
    assert "asked 5s ago, expires in 895s" in out


def test_cli_list_max_age(
    server: str, client: TestClient, clock: Clock[float], capsys: Any, monkeypatch: Any
) -> None:
    old = ask(client, 0)
    clock.now += 600
    new = ask(client, 1)
    code, out, _ = cli(capsys, monkeypatch, server, "list", "--max-age", "5")
    assert code == 0 and new in out and old not in out
    code, out, _ = cli(capsys, monkeypatch, server, "list", "--group", "--max-age", "11")
    assert code == 0 and new in out and old in out


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["list", "--max-age", "0"], "--max-age takes 1 to 10080 minutes"),
        (["list", "--max-age", "10081"], "--max-age takes 1 to 10080 minutes"),
        (["list", "--rejected", "--max-age", "5"], "--max-age is for `list`"),
        (["approve", "a" * 32, "--max-age", "5"], "--max-age is for `list`"),
        (["reject", "a" * 32, "--across-runs"], "--across-runs is for `approve`"),
        (["list", "--across-runs"], "--across-runs is for `approve`"),
    ],
)
def test_cli_usage_errors(
    argv: list[str], message: str, server: str, capsys: Any, monkeypatch: Any
) -> None:
    code, _, err = cli(capsys, monkeypatch, server, *argv)
    assert code == 2 and message in err


def two_runs(client: TestClient, clock: Clock[float]) -> list[str]:
    """Two actions, then a gap of just over RUN_GAP_SECONDS, then two more."""
    ids = [ask(client, 0), ask(client, 1)]
    clock.now += RUN_GAP_SECONDS + 1
    ids += [ask(client, 2)]
    clock.now += RUN_GAP_SECONDS  # exactly the gap: still the same run
    ids += [ask(client, 3)]
    return ids


def test_yes_refuses_to_approve_across_runs(
    server: str,
    client: TestClient,
    store: ApprovalStore,
    clock: Clock[float],
    capsys: Any,
    monkeypatch: Any,
) -> None:
    ids = two_runs(client, clock)
    code, out, err = cli(capsys, monkeypatch, server, "approve", *ids, "--yes")
    assert code == 1
    assert "from 2 separate runs" in out
    assert "2 action(s), asked 4 min ago to 4 min ago" in out
    assert "2 action(s), asked 2 min ago to 0s ago" in out
    assert "refusing to approve actions from separate runs" in err
    assert all(store._items[i].status is Status.PENDING for i in ids)  # nothing changed


def test_across_runs_lets_yes_approve(
    server: str,
    client: TestClient,
    store: ApprovalStore,
    clock: Clock[float],
    capsys: Any,
    monkeypatch: Any,
) -> None:
    ids = two_runs(client, clock)
    code, out, _ = cli(capsys, monkeypatch, server, "approve", *ids, "--yes", "--across-runs")
    assert code == 0 and "Approved 4 actions." in out
    assert "from 2 separate runs" in out  # still warned
    assert all(store._items[i].status is Status.APPROVED for i in ids)


def test_interactive_approve_across_runs_asks_about_all_runs(
    server: str,
    client: TestClient,
    store: ApprovalStore,
    clock: Clock[float],
    capsys: Any,
    monkeypatch: Any,
) -> None:
    ids = two_runs(client, clock)
    code, out, _ = cli(capsys, monkeypatch, server, "approve", *ids, answer="n\n")
    assert code == 1 and "Approve all 4 actions from 2 separate runs? [y/N]" in out
    assert all(store._items[i].status is Status.PENDING for i in ids)
    code, out, _ = cli(capsys, monkeypatch, server, "approve", *ids, answer="y\n")
    assert code == 0
    assert all(store._items[i].status is Status.APPROVED for i in ids)


def test_one_run_is_not_warned_about(
    server: str,
    client: TestClient,
    store: ApprovalStore,
    clock: Clock[float],
    capsys: Any,
    monkeypatch: Any,
) -> None:
    ids = [ask(client, 0)]
    clock.now += RUN_GAP_SECONDS  # exactly the gap: one run
    ids.append(ask(client, 1))
    code, out, _ = cli(capsys, monkeypatch, server, "approve", *ids, "--yes")
    assert code == 0 and "separate runs" not in out


def test_rejecting_across_runs_is_never_blocked(
    server: str,
    client: TestClient,
    store: ApprovalStore,
    clock: Clock[float],
    capsys: Any,
    monkeypatch: Any,
) -> None:
    ids = two_runs(client, clock)
    code, out, _ = cli(capsys, monkeypatch, server, "reject", *ids, "--yes")
    assert code == 0 and "Rejected 4 actions." in out and "separate runs" not in out
    assert all(store._items[i].status is Status.DENIED for i in ids)


def test_runs_split_on_gaps_and_unknown_ages() -> None:
    def item(age: Any) -> dict[str, Any]:
        return {"age_seconds": age}

    assert _runs([]) == []
    assert len(_runs([item(0), item(120), item(240)])) == 1  # each gap is exactly 120
    assert [len(r) for r in _runs([item(500), item(0), item(121)])] == [1, 1, 1]
    assert [len(r) for r in _runs([item(5), item(0), item(400)])] == [2, 1]
    # An age that isn't a plain integer counts as its own run: warn rather than not.
    assert [len(r) for r in _runs([item(None), item(True), item("1"), item(3)])] == [1, 1, 1, 1]
