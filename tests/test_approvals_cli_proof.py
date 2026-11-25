"""`warden approvals` and `warden agent add`: the admin key is only sent to a server that has
proven that it is Warden."""

import io
import json
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server
from proof import Proving, http_answer, raw_impostor, read_message, serving

from warden import approvals_cli, identity
from warden.api import create_app
from warden.approvals import ApprovalStore, Status
from warden.audit import SQLiteAuditLog
from warden.cli import main
from warden.client import NOT_PROVEN

KEY = "cli-admin-key-0123456789abcdefgh"
APPROVAL = "appr-0123456789abcdef"
EVIL_LIST = json.dumps(
    [{"approval_id": APPROVAL, "agent_id": "a", "tool": "t", "arguments": {"to": "evil"}}]
).encode()


def run(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, *argv: str, key: str = KEY
) -> tuple[int, str, str]:
    monkeypatch.setenv("WARDEN_ADMIN_KEY", key)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))
    code = main(["approvals", *argv])
    captured = capsys.readouterr()
    assert key not in captured.out + captured.err
    return code, captured.out, captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["list"],
        ["list", "--group"],
        ["list", "--rejected"],
        ["approve", APPROVAL, "--yes"],
        ["reject", APPROVAL],
        ["lift", APPROVAL, "--yes"],
    ],
)
def test_an_impostor_never_gets_the_admin_key(
    argv: list[str], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def act(sock: socket.socket) -> None:
        read_message(sock)
        sock.sendall(http_answer(EVIL_LIST))

    with raw_impostor(act) as (port, received):
        code, out, err = run(capsys, monkeypatch, *argv, "--warden-url", f"http://127.0.0.1:{port}")
    assert code == 2 and out == "" and NOT_PROVEN in err
    assert received.count(b"HTTP/1.1\r\n") == 1 and b"POST /v1/hello " in received
    assert KEY.encode() not in received and APPROVAL.encode() not in received
    assert b"admin-key" not in received.lower()


def test_an_impostor_that_claims_the_key_is_wrong(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def act(sock: socket.socket) -> None:
        read_message(sock)
        sock.sendall(http_answer(b"{}", "401 Unauthorized"))

    with raw_impostor(act) as (port, received):
        code, _, err = run(capsys, monkeypatch, "list", "--warden-url", f"http://127.0.0.1:{port}")
    assert code == 1 and "is wrong, or what listens at" in err and "was not sent" in err
    assert KEY.encode() not in received


@pytest.fixture
def warden(tmp_path: Path) -> Iterator[tuple[str, TestClient, ApprovalStore]]:
    store = ApprovalStore(ttl_seconds=900)
    log = SQLiteAuditLog(tmp_path / "a.db")
    app = create_app(BASIC_POLICY, audit_log=log, approvals=store, admin_key=KEY)
    with live_server(app) as url:
        yield url, TestClient(app), store


def test_good_path(
    warden: tuple[str, TestClient, ApprovalStore],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, client, store = warden
    body = {"agent_id": "a", "tool": "send_email", "arguments": {"to": "x"}}
    ids = []
    for to in ("x", "y"):
        body["arguments"] = {"to": to}
        ids.append(client.post("/v1/evaluate", json=body).json()["approval_id"])
    flags = ["--warden-url", url]
    assert run(capsys, monkeypatch, "list", "--tool", "send_email", *flags)[0] == 0
    assert run(capsys, monkeypatch, "approve", ids[0], *flags)[0] == 0
    assert run(capsys, monkeypatch, "reject", ids[1], "--yes", *flags)[0] == 0
    assert store._items[ids[0]].status is Status.APPROVED
    assert ids[1] in run(capsys, monkeypatch, "list", "--rejected", *flags)[1]
    assert run(capsys, monkeypatch, "lift", ids[1], "--yes", *flags)[0] == 0
    code, _, err = run(capsys, monkeypatch, "list", *flags, key="w" * 32)
    assert code == 1 and "WARDEN_ADMIN_KEY is wrong" in err


def test_a_key_with_an_accent_works(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both ends of what a header can carry: the derived keys must agree."""
    key = "ÿ é" + "~" * 30
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=key)
    with live_server(app) as url:
        assert run(capsys, monkeypatch, "list", "--warden-url", url, key=key)[0] == 0


@pytest.mark.parametrize("bad", ["\n", "\r", "\x00", "\x1f", "\x7f", "\x9f", "Ā", "\udcff"])
def test_unsendable_keys(bad: str) -> None:
    with pytest.raises(approvals_cli._Unreachable, match="contains characters"):
        approvals_cli._call("http://127.0.0.1:9", KEY + bad, "GET", "/v1/approvals")


# --- An answer that isn't signed correctly doesn't count ------------------------------------


class Fake(Proving):
    secrets = (KEY,)
    change: Callable[["Fake", str], dict[str, str]]

    def answer(self) -> None:
        mac = self.mac(200, EVIL_LIST, {})
        self.raw_reply(200, EVIL_LIST, type(self).change(self, mac))


CHANGES: dict[str, Callable[[Fake, str], dict[str, str]]] = {
    "none": lambda fake, mac: {},
    "flipped": lambda fake, mac: {"Warden-Mac": f"{int(mac, 16) ^ 1:064x}"},
    "status": lambda fake, mac: {"Warden-Mac": fake.mac(401, EVIL_LIST, {})},
    "query": lambda fake, mac: {
        "Warden-Mac": fake.mac(200, EVIL_LIST, {}, target=b"/v1/approvals")
    },
    "agent key": lambda fake, mac: {
        "Warden-Mac": fake.mac(200, EVIL_LIST, {}, key=identity.proof_key("wdn_x"))
    },
}


@pytest.mark.parametrize("which", CHANGES)
def test_unsigned_lists_are_not_shown(
    which: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = type("Handler", (Fake,), {"change": CHANGES[which]})
    with serving(handler) as url:
        flags: Any = ["--agent", "a", "--warden-url", url]
        code, out, err = run(capsys, monkeypatch, "list", *flags)
        assert code == 2 and out == "" and NOT_PROVEN in err
        code, out, err = run(capsys, monkeypatch, "approve", APPROVAL, "--warden-url", url)
        assert code == 2 and out == "" and NOT_PROVEN in err


def test_the_same_list_signed_is_shown(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    handler = type("Handler", (Fake,), {"change": lambda fake, mac: {"Warden-Mac": mac}})
    with serving(handler) as url:
        code, out, _ = run(capsys, monkeypatch, "list", "--agent", "a", "--warden-url", url)
    assert code == 0 and APPROVAL in out
