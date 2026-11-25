"""`warden proxy`: a request id can't be reused while its request is unanswered, so a client
can never take the answer (or the refusal) of one call for another's."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from test_mcp_proxy import (
    ALLOW,
    DENY,
    FakeWarden,
    Session,
    call,
    calls_seen,
    make_config,
    pending,
    run_session,
)

import warden.mcp_proxy as proxy_module

IN_USE = {"code": -32600, "message": "request id already in use"}
PING: dict[str, Any] = {"jsonrpc": "2.0", "method": "ping"}

# Reads and logs every line, answers only when told to: a notification
# "notifications/answer" with params.id makes it answer that id.
SILENT_SERVER = """
import json, os, sys
for line in sys.stdin:
    with open(os.environ["FAKE_MCP_LOG"], "a", encoding="utf-8") as log:
        log.write(line)
    message = json.loads(line)
    if message.get("method") == "notifications/answer":
        print(json.dumps({"jsonrpc": "2.0", "id": message["params"]["id"], "result": {}}))
        sys.stdout.flush()
"""


def silent_config(tmp_path: Path) -> Any:
    log = str(tmp_path / "server.log")
    return make_config(
        tmp_path,
        server={
            "command": sys.executable,
            "args": ["-c", SILENT_SERVER],
            "env": {"FAKE_MCP_LOG": log},
        },
    )


def answer(request_id: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": "notifications/answer", "params": {"id": request_id}}


async def refused(s: Session, message: dict[str, Any], error: dict[str, Any] = IN_USE) -> None:
    """Refused with id null: an error under the reused id would look like the answer to
    the request that is still running."""
    reply = await s.roundtrip(message)
    assert reply["id"] is None and reply["error"] == error


SAME = [(1, 1), ("a", "a"), (1, "1"), ("1", 1), (0, "0"), (None, None)]


@pytest.mark.parametrize(("first", "second"), SAME)
@pytest.mark.parametrize("kind", ["call", "ping", "unknown method", "extra key"])
def test_id_of_a_forwarded_call_cant_be_reused(
    tmp_path: Path, first: Any, second: Any, kind: str
) -> None:
    again: dict[str, Any] = {
        "call": call("echo", {"n": 2}, request_id=second),
        "ping": {**PING, "id": second},
        "unknown method": {**PING, "id": second, "method": "nope"},
        "extra key": {**PING, "id": second, "Method": "x"},
    }[kind]

    async def script(s: Session) -> None:
        s.send(call("echo", {"n": 1}, request_id=first))
        await asyncio.sleep(0.2)  # allowed and sent; the server hasn't answered
        await refused(s, again)

    session, _ = run_session(silent_config(tmp_path), FakeWarden(), script)
    assert [m["params"] for m in session.server_saw()] == [{"name": "echo", "arguments": {"n": 1}}]


@pytest.mark.parametrize(("first", "second"), SAME)
def test_id_of_a_held_call_cant_be_reused(tmp_path: Path, first: Any, second: Any) -> None:
    async def script(s: Session) -> None:
        s.send(call("slow", {}, request_id=first))
        await asyncio.sleep(0.1)
        await refused(s, {**PING, "id": second})
        await refused(s, call("echo", {}, request_id=second))

    session, _ = run_session(
        make_config(tmp_path), FakeWarden({"slow": [pending()], "echo": [ALLOW]}), script
    )
    assert session.server_saw() == []


@pytest.mark.parametrize("method", ["ping", "initialize", "tools/list"])
def test_id_of_a_forwarded_protocol_request_cant_be_reused(tmp_path: Path, method: str) -> None:
    async def script(s: Session) -> None:
        s.send({**PING, "id": 1, "method": method})
        await refused(s, call("echo", {}, request_id=1))

    session, _ = run_session(silent_config(tmp_path), FakeWarden(), script)
    assert calls_seen(session) == []


def test_repeated_key_refusal_doesnt_answer_an_unanswered_request(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send({**PING, "id": 7})
        s.send_raw(b'{"jsonrpc":"2.0","id":"7","method":"ping","method":"x"}\n')
        assert (await s.recv())["id"] is None

    run_session(silent_config(tmp_path), FakeWarden(), script)


@pytest.mark.parametrize("bad", [1.0, True, [1], {"a": 1}])
def test_ids_that_could_equal_another_are_refused(tmp_path: Path, bad: Any) -> None:
    async def script(s: Session) -> None:
        s.send({**PING, "id": 1})
        await refused(
            s, {**PING, "id": bad}, {"code": -32600, "message": "not a JSON-RPC 2.0 message"}
        )

    session, _ = run_session(silent_config(tmp_path), FakeWarden(), script)
    assert len(session.server_saw()) == 1


@pytest.mark.parametrize(
    ("request_id", "ok"),
    [
        (2**53 - 1, True),
        (-(2**53 - 1), True),
        (2**53, False),  # JavaScript reads 2**53 + 1 as the same number
        (-(2**53), False),
        ("x" * 256, True),
        ("x" * 257, False),
    ],
)
def test_id_limits(tmp_path: Path, request_id: Any, ok: bool) -> None:
    async def script(s: Session) -> None:
        for message in ({**PING, "id": request_id}, call("echo", {}, request_id=request_id)):
            if ok:
                assert (await s.roundtrip(message))["id"] == request_id
            else:
                await refused(
                    s, message, {"code": -32600, "message": "request id is too long or too large"}
                )

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert len(session.server_saw()) == (2 if ok else 0)


def test_an_id_is_free_again_after_its_answer(tmp_path: Path) -> None:
    warden = FakeWarden({"no": [DENY]})

    async def script(s: Session) -> None:
        for _ in range(3):
            for message in (
                call("echo", {}, request_id=1),
                call("no", {}, request_id=1),
                call("echo", [], request_id=1),  # refused: bad arguments
                {**PING, "id": 1},
                {**PING, "id": 1, "method": "nope"},
            ):
                reply = await s.roundtrip(message)
                assert reply["id"] == 1, reply
                await asyncio.sleep(0.02)  # let the finished call's task end

    run_session(make_config(tmp_path), warden, script)


def test_only_the_exact_id_frees_it(tmp_path: Path) -> None:
    """A server's answer to "1" is not the answer to 1."""

    async def script(s: Session) -> None:
        s.send({**PING, "id": 1})
        s.send(answer("1"))
        assert (await s.recv())["id"] == "1"
        await refused(s, {**PING, "id": 1})
        s.send(answer(1))
        assert (await s.recv())["id"] == 1
        s.send({**PING, "id": 1})
        await s.nothing_for(0.2)

    session, _ = run_session(silent_config(tmp_path), FakeWarden(), script)
    assert [m["method"] for m in session.server_saw()].count("ping") == 2


def test_answer_to_a_look_alike_of_a_held_id_is_dropped(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send(call("slow", {}, request_id=1))
        await asyncio.sleep(0.1)
        s.send(answer("1"))
        await s.nothing_for(0.2)

    run_session(silent_config(tmp_path), FakeWarden({"slow": [pending()]}), script)


def cancel(request_id: Any) -> dict[str, Any]:
    params = {"requestId": request_id}
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": params}


def test_cancelling_a_forwarded_call_doesnt_free_its_id(tmp_path: Path) -> None:
    """The server may still answer it."""

    async def script(s: Session) -> None:
        s.send(call("echo", {}, request_id=1))
        await asyncio.sleep(0.2)
        s.send(cancel(1))
        await asyncio.sleep(0.1)
        await refused(s, call("echo", {}, request_id=1))

    session, _ = run_session(silent_config(tmp_path), FakeWarden(), script)
    assert len(calls_seen(session)) == 1


def test_cancelling_a_held_call_frees_its_id(tmp_path: Path) -> None:
    """The server never got it, so nobody else can answer it."""

    async def script(s: Session) -> None:
        s.send(call("slow", {}, request_id=1))
        await asyncio.sleep(0.1)
        s.send(cancel(1))
        await asyncio.sleep(0.1)
        assert "result" in await s.roundtrip(call("echo", {}, request_id=1))

    session, _ = run_session(make_config(tmp_path), FakeWarden({"slow": [pending()]}), script)
    assert len(calls_seen(session)) == 1


def test_too_many_unanswered_requests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert proxy_module.MAX_UNANSWERED == 10_000
    monkeypatch.setattr(proxy_module, "MAX_UNANSWERED", 2)

    async def script(s: Session) -> None:
        s.send({**PING, "id": 1})
        s.send(call("echo", {}, request_id=2))
        await asyncio.sleep(0.1)
        for message in ({**PING, "id": 3}, call("echo", {}, request_id=4)):
            reply = await s.roundtrip(message)
            assert reply["id"] == message["id"]
            assert reply["error"]["message"] == "too many unanswered requests"
        s.send(answer(1))
        assert (await s.recv())["id"] == 1
        s.send({**PING, "id": 5})
        await s.nothing_for(0.2)

    session, _ = run_session(silent_config(tmp_path), FakeWarden(), script)
    sent = [m["id"] for m in session.server_saw() if "id" in m]
    assert json.dumps(sent) == "[1, 2, 5]"
