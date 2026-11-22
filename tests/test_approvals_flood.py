"""A reviewer can still work while an agent floods the approval queue.

Found by the stress test: 10 agents x 100 pending approvals full of invisible characters
made a 63 MB list, so `warden approvals list` AND `reject` gave up (answer too large).
Now GET /v1/approvals can be narrowed (?ids=, ?agent_id=, ?tool=), and approve/reject
fetch only the ids they name. Filters narrow what is SHOWN only; decisions still take
exact ids and action hashes.
"""

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server

from warden import approvals_cli
from warden.api import create_app
from warden.approvals import ApprovalStore, Status
from warden.audit import SQLiteAuditLog
from warden.cli import main

KEY = "flood-admin-key-0123456789abcdefg"
ADMIN = {"X-Warden-Admin-Key": KEY}
LIMITS = {"default": {"requests_per_minute": 100000, "max_pending_approvals": 1000}}


def policy(tmp_path: Path) -> Path:
    """The basic test policy with room for a flood (default quota is 100 pending)."""
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({**json.loads(BASIC_POLICY.read_text()), "limits": LIMITS}))
    return path


@pytest.fixture
def store() -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900)


@pytest.fixture
def client(tmp_path: Path, store: ApprovalStore) -> TestClient:
    app = create_app(
        policy(tmp_path),
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        approvals=store,
        admin_key=KEY,
    )
    return TestClient(app)


def queue(client: TestClient, n: int, agent: str, to: str = "x@example.com") -> list[str]:
    ids = []
    for i in range(n):
        body = {"agent_id": agent, "tool": "send_email", "arguments": {"to": f"{i}{to}"}}
        answer = client.post("/v1/evaluate", json=body).json()
        ids.append(answer["approval_id"])
    return ids


def listed(client: TestClient, query: str) -> list[str]:
    answer = client.get("/v1/approvals" + query, headers=ADMIN)
    assert answer.status_code == 200
    return [item["approval_id"] for item in answer.json()]


# --- Filters on GET /v1/approvals -----------------------------------------------------------


def test_ids_filter_shows_only_those(client: TestClient) -> None:
    ids = queue(client, 5, "agent-1")
    assert listed(client, f"?ids={ids[3]},{ids[1]}") == [ids[1], ids[3]]  # oldest first


def test_unknown_ids_are_just_absent(client: TestClient) -> None:
    ids = queue(client, 2, "agent-1")
    assert listed(client, f"?ids={ids[0]},{'z' * 32}") == [ids[0]]


def test_agent_and_tool_filters(client: TestClient) -> None:
    mine = queue(client, 2, "agent-1")
    queue(client, 3, "agent-2")
    assert listed(client, "?agent_id=agent-1") == mine
    assert listed(client, "?agent_id=agent-1&tool=send_email") == mine
    assert listed(client, "?agent_id=agent-1&tool=read_file") == []
    assert len(listed(client, "?tool=send_email")) == 5


def test_filters_work_on_the_grouped_list(client: TestClient) -> None:
    mine = queue(client, 2, "agent-1")
    queue(client, 3, "agent-2")
    answer = client.get(f"/v1/approvals?group=true&ids={mine[1]}", headers=ADMIN).json()
    assert len(answer["groups"]) == 1
    group = answer["groups"][0]
    assert (group["agent_id"], group["count"]) == ("agent-1", 1)
    assert group["approvals"][0]["approval_id"] == mine[1]
    empty = client.get("/v1/approvals?group=true&agent_id=nobody", headers=ADMIN).json()
    assert empty == {"groups": []}


@pytest.mark.parametrize(
    "query",
    [
        "?ids=",
        "?ids=short",
        "?ids=" + "a" * 32 + ",",
        "?ids=" + "a" * 32 + ",,",
        "?ids=" + ",".join(f"{i:032d}" for i in range(101)),
        "?ids=" + "a" * 32 + "%20",
        "?agent_id=bad%20agent",
        "?agent_id=",
        "?tool=Send_Email",
        "?tool=" + "t" * 65,
    ],
)
def test_malformed_filters_are_refused(client: TestClient, query: str) -> None:
    queue(client, 1, "agent-1")
    answer = client.get("/v1/approvals" + query, headers=ADMIN)
    assert answer.status_code == 422
    assert "x@example.com" not in answer.text  # never echoes arguments


def test_hundred_ids_fit(client: TestClient) -> None:
    ids = queue(client, 100, "agent-1")
    assert listed(client, "?ids=" + ",".join(ids)) == ids


def test_filters_need_the_admin_key(client: TestClient) -> None:
    ids = queue(client, 1, "agent-1")
    assert client.get(f"/v1/approvals?ids={ids[0]}").status_code == 401


def test_a_filter_never_decides_anything(client: TestClient, store: ApprovalStore) -> None:
    """Narrowing the view is read-only: no filter on GET changes any approval, and the
    decide endpoint has no filters (extra fields are refused)."""
    ids = queue(client, 3, "agent-1")
    listed(client, f"?ids={ids[0]}&agent_id=agent-1&tool=send_email")
    assert all(store._items[i].status is Status.PENDING for i in ids)
    body = {"ids": [ids[0]], "approve": False, "agent_id": "agent-1"}
    assert client.post("/v1/approvals/decide", json=body, headers=ADMIN).status_code == 422
    assert all(store._items[i].status is Status.PENDING for i in ids)


# --- The flood, through the CLI --------------------------------------------------------------


@pytest.fixture
def flooded(
    tmp_path: Path, store: ApprovalStore, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[str, list[str], list[str]]]:
    """A server where `flood` has many pending approvals full of invisible characters
    and `good` has two ordinary ones. The CLI's answer limit is shrunk so the full list
    is 'too large', like the 63 MB list in the stress test."""
    app = create_app(
        policy(tmp_path),
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        approvals=store,
        admin_key=KEY,
    )
    client = TestClient(app)
    flood = queue(client, 60, "flood", to="​" * 2000 + "@example.com")
    good = queue(client, 2, "good")
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    monkeypatch.delenv("WARDEN_URL", raising=False)
    monkeypatch.setattr(approvals_cli, "MAX_RESPONSE_BYTES", 200_000)
    with live_server(app) as url:
        yield url, flood, good


def cli(capsys: Any, monkeypatch: Any, *argv: str) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    code = main(["approvals", *argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_full_list_is_too_large_and_says_how_to_narrow(
    flooded: tuple[str, list[str], list[str]], capsys: Any, monkeypatch: Any
) -> None:
    url, _, _ = flooded
    code, _, err = cli(capsys, monkeypatch, "list", "--warden-url", url)
    assert code == 2 and "too large" in err and "--agent" in err


def test_list_one_agent_during_a_flood(
    flooded: tuple[str, list[str], list[str]], capsys: Any, monkeypatch: Any
) -> None:
    url, flood, good = flooded
    code, out, _ = cli(capsys, monkeypatch, "list", "--agent", "good", "--warden-url", url)
    assert code == 0
    assert all(i in out for i in good) and not any(i in out for i in flood)
    code, out, _ = cli(
        capsys, monkeypatch, "list", "--group", "--agent", "good", "--tool", "send_email",
        "--warden-url", url,
    )  # fmt: skip
    assert code == 0 and "Agent good, tool send_email: 2 action(s)" in out


def test_reject_and_approve_still_work_during_a_flood(
    flooded: tuple[str, list[str], list[str]],
    store: ApprovalStore,
    capsys: Any,
    monkeypatch: Any,
) -> None:
    url, flood, good = flooded
    code, out, _ = cli(capsys, monkeypatch, "reject", "--yes", flood[0], "--warden-url", url)
    assert code == 0 and "Rejected 1 actions." in out
    assert "\\u200b" in out  # the reviewer still saw the hidden characters, escaped
    code, out, _ = cli(capsys, monkeypatch, "approve", "--yes", *good, "--warden-url", url)
    assert code == 0 and "Approved 2 actions." in out
    assert store._items[flood[0]].status is Status.DENIED
    assert all(store._items[i].status is Status.APPROVED for i in good)
    assert all(store._items[i].status is Status.PENDING for i in flood[1:])
