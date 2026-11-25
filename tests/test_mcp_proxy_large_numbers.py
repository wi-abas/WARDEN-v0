"""`warden proxy`: 1e999 is valid JSON, but Python reads it as infinity and would write the
invalid JSON `Infinity`. Refused both ways, and the waiting request gets an error."""

import sys
from pathlib import Path
from typing import Any

import pytest
from test_mcp_proxy import FakeWarden, Session, make_config, run_session

from warden.mcp_proxy import recover_id

TOO_LARGE = {"code": -32600, "message": "number too large in message (refused by Warden)"}
# Answers request 1 with the line given as its argument.
SERVER = """
import os, sys
for line in sys.stdin:
    with open(os.environ["FAKE_MCP_LOG"], "a", encoding="utf-8") as log:
        log.write(line)
    print(sys.argv[1], flush=True)
"""
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


@pytest.mark.parametrize("number", ["1e999", "-1e999", "1.5E+400", '[{"deep": 1e309}]'])
@pytest.mark.parametrize("method", ["tools/call", "initialize"])
def test_request_is_refused(tmp_path: Path, number: str, method: str) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        params = f'{{"name":"echo","arguments":{{"n":{number}}}}}'
        line = f'{{"jsonrpc":"2.0","id":7,"method":"{method}","params":{params}}}\n'
        s.send_raw(line.encode())
        assert await s.recv() == {"jsonrpc": "2.0", "id": 7, "error": TOO_LARGE}

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert session.server_saw() == [] and warden.asked == []


def test_largest_float_still_passes(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send_raw(b'{"jsonrpc":"2.0","id":7,"method":"ping","params":{"n":1e308}}\n')
        assert (await s.recv())["id"] == 7

    run_session(make_config(tmp_path), FakeWarden(), script)


def with_server(tmp_path: Path, answer: str) -> Any:
    return make_config(
        tmp_path,
        server={
            "command": sys.executable,
            "args": ["-c", SERVER, answer],
            "env": {"FAKE_MCP_LOG": str(tmp_path / "server.log")},
        },
    )


@pytest.mark.parametrize(
    "answer",
    [
        '{"jsonrpc":"2.0","id":1,"result":{"n":1e999}}',
        '{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x","data":-1e999}}',
        '{"jsonrpc":"2.0","id":1,"result":{"a":1,"a":2}}',
    ],
)
def test_server_answer_becomes_an_error(tmp_path: Path, answer: str) -> None:
    async def script(s: Session) -> None:
        for _ in range(2):  # and the id is free again
            reply = await s.roundtrip(PING)
            error = {"code": -32603, "message": "server answer refused by Warden"}
            assert reply == {"jsonrpc": "2.0", "id": 1, "error": error}

    run_session(with_server(tmp_path, answer), FakeWarden(), script)


@pytest.mark.parametrize(
    "answer",
    [
        '{"jsonrpc":"2.0","id":"1","result":1e999}',  # not the exact id
        '{"jsonrpc":"2.0","id":2,"result":1e999}',  # nobody asked
        '{"jsonrpc":"2.0","id":1,"method":"roots/list","params":{"n":1e999}}',
        '{"jsonrpc":"2.0","method":"notifications/x","params":{"n":1e999}}',
        '{"jsonrpc":"2.0","id":1,"id":1,"result":1e999}',
        '{"jsonrpc":"2.0","id":1,"result":1,"result":2}',
        '{"jsonrpc":"2.0","id":1,"result":NaN}',
    ],
)
def test_other_server_messages_answer_nothing(tmp_path: Path, answer: str) -> None:
    async def script(s: Session) -> None:
        s.send(PING)
        await s.nothing_for(0.5)
        assert "1" in s.proxy._unanswered

    run_session(with_server(tmp_path, answer), FakeWarden(), script)


def test_an_id_still_waiting_isnt_answered_by_a_refusal(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send(PING)
        s.send_raw(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"n":1e999}}\n')
        assert await s.recv() == {"jsonrpc": "2.0", "id": None, "error": TOO_LARGE}

    run_session(with_server(tmp_path, ""), FakeWarden(), script)


def test_recover_id_answers_only() -> None:
    assert recover_id(b'{"jsonrpc":"2.0","id":1,"result":1e999}', answers_only=True) == 1
    assert recover_id(b'{"id":1,"result":1e999}', answers_only=True) is None
