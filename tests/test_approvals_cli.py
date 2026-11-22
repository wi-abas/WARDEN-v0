"""`warden approvals list|approve|reject` against a real local server."""

import io
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server

from warden import approvals_cli
from warden.api import create_app
from warden.approvals import ApprovalStore, Status, _new_approval_id
from warden.audit import SQLiteAuditLog
from warden.cli import main

KEY = "cli-admin-key-0123456789abcdefgh"


@pytest.fixture
def store() -> ApprovalStore:
    return ApprovalStore(ttl_seconds=900)


@pytest.fixture
def server(tmp_path: Path, store: ApprovalStore) -> Iterator[tuple[str, TestClient]]:
    app = create_app(
        BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), approvals=store, admin_key=KEY
    )
    with live_server(app) as url:
        yield url, TestClient(app)


@pytest.fixture(autouse=True)
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    monkeypatch.delenv("WARDEN_URL", raising=False)


def queue(client: TestClient, n: int, agent: str = "agent-1", prefix: str = "p") -> list[str]:
    ids = []
    for i in range(n):
        body = {"agent_id": agent, "tool": "send_email", "arguments": {"to": f"{prefix}{i}@x.com"}}
        ids.append(client.post("/v1/evaluate", json=body).json()["approval_id"])
    return ids


def cli(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    *argv: str,
    answer: str = "",
) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(answer))
    code = main(["approvals", *argv])
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err  # the key is never printed
    return code, captured.out, captured.err


def test_list(server: tuple[str, TestClient], capsys: Any, monkeypatch: Any) -> None:
    url, client = server
    ids = queue(client, 2)
    code, out, _ = cli(capsys, monkeypatch, "list", "--warden-url", url)
    assert code == 0
    assert all(i in out for i in ids)
    assert '"to": "p0@x.com"' in out and '"to": "p1@x.com"' in out
    assert out.count("Agent agent-1, tool send_email") == 2


def test_list_grouped(server: tuple[str, TestClient], capsys: Any, monkeypatch: Any) -> None:
    url, client = server
    mine = queue(client, 2)
    theirs = queue(client, 1, agent="agent-2")
    monkeypatch.setenv("WARDEN_URL", url)
    code, out, _ = cli(capsys, monkeypatch, "list", "--group")
    assert code == 0
    assert "Agent agent-1, tool send_email: 2 action(s)" in out
    assert "Agent agent-2, tool send_email: 1 action(s)" in out
    assert out.index(mine[0]) < out.index(mine[1]) < out.index(theirs[0])


def test_list_empty(server: tuple[str, TestClient], capsys: Any, monkeypatch: Any) -> None:
    code, out, _ = cli(capsys, monkeypatch, "list", "--warden-url", server[0])
    assert (code, out) == (0, "No pending approvals.\n")


def test_hidden_characters_never_reach_the_terminal(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    tricky = "boss@x.com‮\x1b[2J​ｅ"
    client.post(
        "/v1/evaluate",
        json={"agent_id": "a", "tool": "send_email", "arguments": {"to": tricky, "é": 1}},
    )
    code, out, _ = cli(capsys, monkeypatch, "list", "--group", "--warden-url", url)
    assert code == 0
    assert out.isascii() and "\x1b" not in out
    assert "WARNING: contains hidden or look-alike characters" in out


def test_approve_with_yes(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 3)
    code, out, _ = cli(capsys, monkeypatch, "approve", *ids, "--warden-url", url, answer="y\n")
    assert code == 0
    assert "Approve these 3 actions? [y/N]" in out and "Approved 3 actions." in out
    assert all(i in out for i in ids) and '"to": "p2@x.com"' in out
    assert all(store._items[i].status is Status.APPROVED for i in ids)


def test_answer_no_changes_nothing(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 2)
    for answer in ["n\n", "\n", "", "yess\n", "approve\n"]:
        code, out, _ = cli(capsys, monkeypatch, "approve", *ids, "--warden-url", url, answer=answer)
        assert code == 1 and "Nothing changed." in out
    assert all(store._items[i].status is Status.PENDING for i in ids)


def test_yes_flag_skips_the_question(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 2)
    code, out, _ = cli(capsys, monkeypatch, "reject", *ids, "--yes", "--warden-url", url)
    assert code == 0 and "[y/N]" not in out and "Rejected 2 actions." in out
    assert '"to": "p0@x.com"' in out  # still shown
    assert all(store._items[i].status is Status.DENIED for i in ids)


def test_unknown_id_is_refused_before_asking(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 2)
    code, out, err = cli(capsys, monkeypatch, "approve", *ids, "q" * 32, "--warden-url", url)
    assert code == 1 and "[y/N]" not in out
    assert f"not pending (unknown, expired or already decided): {'q' * 32}" in err
    assert all(store._items[i].status is Status.PENDING for i in ids)


def test_mixed_agents_are_refused_before_asking(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = [*queue(client, 1), *queue(client, 1, agent="agent-2")]
    code, out, err = cli(capsys, monkeypatch, "approve", *ids, "--yes", "--warden-url", url)
    assert code == 1 and "one agent and one tool" in err
    assert all(store._items[i].status is Status.PENDING for i in ids)


def test_server_refusal_after_showing(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    """Someone else decided one between the list and the decision: all or nothing."""
    url, client = server
    ids = queue(client, 2)
    real_confirm = approvals_cli._confirm

    def decide_one_meanwhile(*args: Any) -> bool:
        client.post(f"/v1/approvals/{ids[1]}/deny", headers={"X-Warden-Admin-Key": KEY})
        return real_confirm(*args)

    monkeypatch.setattr(approvals_cli, "_confirm", decide_one_meanwhile)
    code, _, err = cli(capsys, monkeypatch, "approve", *ids, "--warden-url", url, answer="yes\n")
    assert code == 1
    assert f"refused: {ids[1]}: already decided" in err
    assert "nothing changed" in err
    assert store._items[ids[0]].status is Status.PENDING


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["approve"], "needs at least one approval id"),
        (["reject", "a" * 32, "a" * 32], "listed more than once"),
        (["approve", "bad id!"], "not an approval id"),
        (["approve", *[f"{i:032d}" for i in range(101)]], "at most 100"),
        (["list", "a" * 32], "takes no ids"),
        (["list", "--warden-url", "http://example.com:80"], "this machine"),
        (["approve", "a" * 32, "--agent", "agent-1"], "are for `list`"),
        (["list", "--agent", "bad agent!"], "not an agent id or tool name"),
        (["list", "--tool", "Bad-Tool"], "not an agent id or tool name"),
    ],
)
def test_usage_errors(capsys: Any, monkeypatch: Any, argv: list[str], message: str) -> None:
    code, _, err = cli(capsys, monkeypatch, *argv)
    assert code == 2 and message in err


def test_missing_admin_key(capsys: Any, monkeypatch: Any) -> None:
    monkeypatch.delenv("WARDEN_ADMIN_KEY")
    code, _, err = cli(capsys, monkeypatch, "list")
    assert code == 2 and "WARDEN_ADMIN_KEY" in err


def test_no_admin_key_flag(capsys: Any, monkeypatch: Any) -> None:
    with pytest.raises(SystemExit) as exit_:
        main(["approvals", "list", "--admin-key", KEY])
    assert exit_.value.code == 2


def test_wrong_admin_key(server: tuple[str, TestClient], capsys: Any, monkeypatch: Any) -> None:
    url, client = server
    ids = queue(client, 1)
    monkeypatch.setenv("WARDEN_ADMIN_KEY", "w" * 32)
    for argv in (["list"], ["approve", *ids, "--yes"]):
        code, _, err = cli(capsys, monkeypatch, *argv, "--warden-url", url)
        assert code == 1 and "WARDEN_ADMIN_KEY is wrong" in err
        assert "w" * 32 not in err


def test_wrong_key_on_the_decision(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 1)
    real_call = approvals_cli._call

    def key_changed(url: str, key: str, method: str, path: str, body: Any = None) -> Any:
        return real_call(url, key if method == "GET" else "x" * 32, method, path, body)

    monkeypatch.setattr(approvals_cli, "_call", key_changed)
    code, _, err = cli(capsys, monkeypatch, "approve", *ids, "--yes", "--warden-url", url)
    assert code == 1 and "WARDEN_ADMIN_KEY is wrong" in err


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def test_server_down(capsys: Any, monkeypatch: Any) -> None:
    url = f"http://127.0.0.1:{free_port()}"
    for argv in (["list"], ["approve", "a" * 32, "--yes"]):
        code, _, err = cli(capsys, monkeypatch, *argv, "--warden-url", url)
        assert code == 2 and "can't reach Warden" in err


@pytest.mark.parametrize(
    ("status", "body", "message"),
    [
        (500, b"<html>", "isn't JSON"),
        (200, b'{"not": "a list"}', "unexpected answer"),
        (200, b"[1]", "unexpected answer"),
        (503, b'{"error": "x"}', "HTTP 503"),
    ],
)
def test_odd_answers(capsys: Any, monkeypatch: Any, status: int, body: bytes, message: str) -> None:
    import json

    def fake(url: str, key: str, method: str, path: str, data: Any = None) -> Any:
        try:
            return status, json.loads(body)
        except ValueError:
            raise approvals_cli._Unreachable("Warden at x sent something that isn't JSON") from None

    monkeypatch.setattr(approvals_cli, "_call", fake)
    code, _, err = cli(capsys, monkeypatch, "list")
    assert code == 2 and message in err


def test_odd_group_answer(capsys: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(approvals_cli, "_call", lambda *a, **k: (200, {"groups": "x"}))
    code, _, err = cli(capsys, monkeypatch, "list", "--group")
    assert code == 2 and "unexpected answer" in err
    monkeypatch.setattr(
        approvals_cli, "_call", lambda *a, **k: (200, {"groups": [{"approvals": [1]}]})
    )
    code, _, err = cli(capsys, monkeypatch, "list", "--group")
    assert code == 2 and "unexpected answer" in err


def test_decision_error_without_failures(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 1)
    real_call = approvals_cli._call

    def broken(url: str, key: str, method: str, path: str, body: Any = None) -> Any:
        if method == "POST":
            return 503, {"error": "audit log unavailable, nothing changed"}
        return real_call(url, key, method, path, body)

    monkeypatch.setattr(approvals_cli, "_call", broken)
    code, _, err = cli(capsys, monkeypatch, "approve", *ids, "--yes", "--warden-url", url)
    assert code == 1 and "audit log unavailable, nothing changed" in err


def test_huge_answer_is_refused(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    queue(client, 2)
    monkeypatch.setattr(approvals_cli, "MAX_RESPONSE_BYTES", 10)
    code, _, err = cli(capsys, monkeypatch, "list", "--warden-url", url)
    assert code == 2 and "too large" in err


def test_ids_never_start_with_a_dash(monkeypatch: Any) -> None:

    tokens = iter(["-starts-with-a-dash-0123456789ab", "fine-0123456789abcdefghijklmnopq"])
    monkeypatch.setattr("warden.approvals.secrets.token_urlsafe", lambda n: next(tokens))
    assert _new_approval_id() == "fine-0123456789abcdefghijklmnopq"


def test_dash_ids_work_after_double_dash(
    server: tuple[str, TestClient], store: ApprovalStore, capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    [approval_id] = queue(client, 1)
    dashed = "-" + approval_id[1:]
    store._items[dashed] = store._items.pop(approval_id)
    store._items[dashed].approval_id = dashed
    code, out, _ = cli(capsys, monkeypatch, "approve", "--yes", "--warden-url", url, "--", dashed)
    assert code == 0 and "Approved 1 actions." in out


def test_non_json_answer_from_a_real_server(capsys: Any, monkeypatch: Any) -> None:
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse

    app = FastAPI()
    app.get("/v1/approvals")(lambda: PlainTextResponse("<html>"))
    with live_server(app) as url:
        code, _, err = cli(capsys, monkeypatch, "list", "--warden-url", url)
    assert code == 2 and "isn't JSON" in err


def test_odd_failure_entries_are_skipped(
    server: tuple[str, TestClient], capsys: Any, monkeypatch: Any
) -> None:
    url, client = server
    ids = queue(client, 1)
    real_call = approvals_cli._call

    def odd(url: str, key: str, method: str, path: str, body: Any = None) -> Any:
        if method == "POST":
            return 409, {"failed": ["\x1b[2J", {"id": ids[0], "reason": "x\x1b"}]}
        return real_call(url, key, method, path, body)

    monkeypatch.setattr(approvals_cli, "_call", odd)
    code, _, err = cli(capsys, monkeypatch, "approve", *ids, "--yes", "--warden-url", url)
    assert code == 1 and "\x1b" not in err and f"refused: {ids[0]}: x\\u001b" in err


def test_deeply_nested_answer_is_refused_cleanly(capsys: Any, monkeypatch: Any) -> None:
    """A misbehaving server can't crash the CLI with JSON nested too deep to parse."""
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse

    app = FastAPI()
    app.get("/v1/approvals")(lambda: PlainTextResponse("[" * 100_000 + "]" * 100_000))
    with live_server(app) as url:
        code, _, err = cli(capsys, monkeypatch, "list", "--warden-url", url)
    assert code == 2 and "isn't JSON" in err
