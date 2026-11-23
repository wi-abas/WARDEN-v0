"""`warden proxy`: every tools/call is checked; nothing unchecked reaches the server."""

import asyncio
import io
import json
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, live_server
from pydantic import JsonValue

from warden import cli
from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import Answer, WardenClient
from warden.mcp_proxy import (
    MAX_IN_FLIGHT,
    ConfigError,
    McpProxy,
    ProxyConfig,
    load_config,
    read_line,
    recover_id,
    stdin_reader,
)
from warden.models import Decision

FAKE_SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
ALLOW = Answer(Decision.ALLOW, "ok")
DENY = Answer(Decision.DENY, "no deleting")
HASH = "a" * 64


class FakeWarden:
    """Scripted answers per tool; records every question."""

    def __init__(self, answers: dict[str, list[Answer]] | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[tuple[str, dict[str, JsonValue], str | None]] = []

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        self.asked.append((tool, json.loads(json.dumps(arguments)), approval_id))
        script = self.answers.get(tool, [ALLOW])
        return script.pop(0) if len(script) > 1 else script[0]


def pending(approval_id: str = "appr-0123456789abcdef") -> Answer:
    return Answer(Decision.REQUIRE_APPROVAL, "needs a human", approval_id, HASH)


def make_config(tmp_path: Path, **extra: Any) -> ProxyConfig:
    data: dict[str, Any] = {
        "server": {
            "command": sys.executable,
            "args": [str(FAKE_SERVER)],
            "env": {"FAKE_MCP_LOG": str(tmp_path / "server.log")},
        },
        "approval": {"mode": "wait", "timeout_seconds": 5, "poll_seconds": 0.01},
    }
    data.update(extra)
    return ProxyConfig.model_validate(data, strict=False)


class Session:
    """Drives one proxy session: send client lines, read what the client gets back."""

    def __init__(self, config: ProxyConfig, checker: Any) -> None:
        self.inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.outbox: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.proxy = McpProxy(config, checker, self.inbox.get, self._write)
        self.log = Path(config.server.env["FAKE_MCP_LOG"])

    def _write(self, data: bytes) -> None:
        assert data.endswith(b"\n") and data.count(b"\n") == 1
        self.outbox.put_nowait(json.loads(data))

    def send_raw(self, line: bytes | None) -> None:
        self.inbox.put_nowait(line)

    def send(self, message: dict[str, Any]) -> None:
        self.send_raw(json.dumps(message).encode() + b"\n")

    async def recv(self, timeout: float = 5) -> dict[str, Any]:
        return await asyncio.wait_for(self.outbox.get(), timeout)

    async def nothing_for(self, seconds: float) -> None:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(self.outbox.get(), seconds)

    def server_saw(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    async def roundtrip(self, message: dict[str, Any]) -> dict[str, Any]:
        self.send(message)
        return await self.recv()


def run_session(
    config: ProxyConfig, checker: Any, script: Callable[[Session], Awaitable[None]]
) -> tuple[Session, int]:
    async def main() -> tuple[Session, int]:
        session = Session(config, checker)
        running = asyncio.create_task(session.proxy.run())
        try:
            await script(session)
        finally:
            session.send_raw(b"")  # client closes stdin
        code = await asyncio.wait_for(running, 10)
        return session, code

    return asyncio.run(main())


def call(name: str, arguments: Any = None, request_id: Any = 1) -> dict[str, Any]:
    params: dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


def echoed(reply: dict[str, Any]) -> dict[str, Any]:
    text = reply["result"]["content"][0]["text"]
    data: dict[str, Any] = json.loads(text)
    return data


def calls_seen(session: Session) -> list[dict[str, Any]]:
    return [m for m in session.server_saw() if m.get("method") == "tools/call"]


# --- Decisions ------------------------------------------------------------------------


def test_allowed_call_reaches_server_with_exact_arguments(tmp_path: Path) -> None:
    warden = FakeWarden()
    args = {"path": "/w/a.txt", "n": [1, 2.5, {"deep": "é"}], "big": 10**30}

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", args))
        assert reply["id"] == 1
        assert echoed(reply) == {"name": "echo", "arguments": args}

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert warden.asked == [("echo", args, None)]
    assert calls_seen(session)[0]["params"]["arguments"] == args


def test_denied_call_never_reaches_server(tmp_path: Path) -> None:
    warden = FakeWarden({"delete_file": [DENY]})

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("delete_file", {"path": "/x"}, request_id="r1"))
        assert reply == {
            "jsonrpc": "2.0",
            "id": "r1",
            "result": {
                "content": [{"type": "text", "text": "Blocked by Warden: no deleting"}],
                "isError": True,
            },
        }

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert calls_seen(session) == []


def test_missing_arguments_checked_as_empty(tmp_path: Path) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(call("echo")))["arguments"] is None

    run_session(make_config(tmp_path), warden, script)
    assert warden.asked == [("echo", {}, None)]


def test_tool_prefix_is_added_for_warden_only(tmp_path: Path) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(call("echo", {})))["name"] == "echo"

    run_session(make_config(tmp_path, tool_prefix="fs."), warden, script)
    assert warden.asked[0][0] == "fs.echo"


class Raising:
    def evaluate(self, *args: object) -> Answer:
        raise RuntimeError("boom")


def test_checker_crash_is_deny(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {}))
        assert reply["result"]["isError"] is True

    session, _ = run_session(make_config(tmp_path), Raising(), script)
    assert calls_seen(session) == []


def test_warden_unreachable_is_deny(tmp_path: Path) -> None:
    checker = WardenClient("http://127.0.0.1:9", timeout=0.5)

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {}))
        assert reply["result"]["content"][0]["text"] == "Blocked by Warden: Warden unreachable"

    session, _ = run_session(make_config(tmp_path), checker, script)
    assert calls_seen(session) == []


def test_too_large_call_says_too_large_not_unreachable(tmp_path: Path) -> None:
    # Nothing listens on port 9: the size check answers before anything is sent.
    checker = WardenClient("http://127.0.0.1:9", timeout=0.5)

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {"blob": "x" * 100_000}))
        assert reply["result"]["isError"] is True
        assert reply["result"]["content"][0]["text"] == (
            "Blocked by Warden: request too large for Warden (limit 64 KB)"
        )

    session, _ = run_session(make_config(tmp_path), checker, script)
    assert calls_seen(session) == []


# --- Approvals ------------------------------------------------------------------------


def test_wait_mode_forwards_after_approval(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending(), pending(), pending(), ALLOW]})

    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(call("echo", {"a": 1})))["arguments"] == {"a": 1}

    run_session(make_config(tmp_path), warden, script)
    # First ask has no id; every retry carries the approval id and the same arguments.
    assert warden.asked[0] == ("echo", {"a": 1}, None)
    assert all(a == ("echo", {"a": 1}, "appr-0123456789abcdef") for a in warden.asked[1:])


def test_wait_mode_human_says_no(tmp_path: Path) -> None:
    warden = FakeWarden(
        {"echo": [pending(), pending(), Answer(Decision.DENY, "denied by a human")]}
    )

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {}))
        assert reply["result"]["content"][0]["text"] == "Blocked by Warden: denied by a human"

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert calls_seen(session) == []


def test_wait_mode_times_out(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 0.2, "poll_seconds": 0.01}
    )

    async def script(s: Session) -> None:
        reply = await s.roundtrip(call("echo", {}))
        assert "timed out" in reply["result"]["content"][0]["text"]

    session, _ = run_session(config, warden, script)
    assert calls_seen(session) == []


def test_error_mode_answers_pending_then_allows_retry(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending(), pending(), pending(), ALLOW]})
    config = make_config(tmp_path, approval={"mode": "error"})

    async def script(s: Session) -> None:
        first = await s.roundtrip(call("echo", {}))
        text = first["result"]["content"][0]["text"]
        assert first["result"]["isError"] and "appr-0123456789abcdef" in text
        assert calls_seen(s) == []
        second = await s.roundtrip(call("echo", {}, request_id=2))
        assert echoed(second)["name"] == "echo"

    run_session(config, warden, script)


def test_approval_without_id_is_deny(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [Answer(Decision.REQUIRE_APPROVAL, "x")]})

    async def script(s: Session) -> None:
        assert (await s.roundtrip(call("echo", {})))["result"]["isError"] is True

    run_session(make_config(tmp_path), warden, script)


def test_cancelled_call_stops_waiting_and_is_never_forwarded(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 1, "poll_seconds": 0.01}
    )

    async def script(s: Session) -> None:
        s.send(call("echo", {}, request_id=7))
        await asyncio.sleep(0.1)
        s.send(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 7},
            }
        )
        await s.nothing_for(0.2)
        # Other traffic still flows while (and after) a call waits.
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 8, "method": "ping"}))["id"] == 8

    session, _ = run_session(config, warden, script)
    assert calls_seen(session) == []


def test_other_messages_flow_while_a_call_waits(tmp_path: Path) -> None:
    warden = FakeWarden({"slow": [pending()], "echo": [ALLOW]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 1, "poll_seconds": 0.01}
    )

    async def script(s: Session) -> None:
        s.send(call("slow", {}, request_id=1))
        reply = await s.roundtrip(call("echo", {}, request_id=2))
        assert reply["id"] == 2

    run_session(config, warden, script)


def test_too_many_calls_in_flight(tmp_path: Path) -> None:
    warden = FakeWarden({"slow": [pending()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 1, "poll_seconds": 0.05}
    )

    async def script(s: Session) -> None:
        for i in range(MAX_IN_FLIGHT):
            s.send(call("slow", {}, request_id=i))
        await asyncio.sleep(0.3)
        reply = await s.roundtrip(call("slow", {}, request_id="one-too-many"))
        assert reply["id"] == "one-too-many"
        assert "too many" in reply["result"]["content"][0]["text"]

    run_session(config, warden, script)


def test_reused_request_id_while_in_flight(tmp_path: Path) -> None:
    warden = FakeWarden({"slow": [pending()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 1, "poll_seconds": 0.05}
    )

    async def script(s: Session) -> None:
        s.send(call("slow", {}, request_id=5))
        await asyncio.sleep(0.1)
        reply = await s.roundtrip(call("slow", {}, request_id=5))
        assert reply["error"]["message"] == "request id already in use"

    run_session(config, warden, script)


# --- Refused messages -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "code"),
    [
        # A first-wins parser in the server would see tools/call; Python sees ping.
        (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping"}', -32600),
        (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            b'{"name":"echo","arguments":{"p":"/ok","p":"/etc/passwd"}}}',
            -32600,
        ),
        (b"not json", -32700),
        (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"e","arguments":'
            b'{"n":NaN}}}',
            -32700,
        ),
        (b'[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}]', -32600),
        (b'"hello"', -32600),
        (b'{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"echo"}}', -32600),
        (b'{"jsonrpc":"2.0","id":{"x":1},"method":"tools/call","params":{"name":"echo"}}', -32600),
        (b'{"jsonrpc":"2.0","id":1.5,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600),
        (b'{"jsonrpc":"2.0","id":1,"method":5}', -32600),
    ],
)
def test_refused_messages_are_never_forwarded(tmp_path: Path, line: bytes, code: int) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        s.send_raw(line + b"\n")
        reply = await s.recv()
        assert reply["error"]["code"] == code
        assert "result" not in reply

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert session.server_saw() == []
    assert warden.asked == []


@pytest.mark.parametrize(
    ("line", "expected_id"),
    [
        # The id is unambiguous: the client gets its error under its own request id.
        (b'{"jsonrpc":"2.0","id":7,"method":"tools/call","method":"ping"}', 7),
        (b'{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"n":1,"n":2}}', "a"),
        (b'{"jsonrpc":"2.0","params":{"id":1,"id":2},"id":null,"method":"x","method":"y"}', None),
        # Ambiguous or unusable: answered with id null, as before.
        (b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}', None),
        (b'{"jsonrpc":"2.0","id":1.5,"method":"ping","method":"x"}', None),
        (b'{"jsonrpc":"2.0","id":{"k":1},"method":"ping","method":"x"}', None),
        (b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping","method":"x"}', None),
        (b'{"jsonrpc":"2.0","method":"ping","method":"x","params":{"id":3}}', None),
        (b'[{"id":1,"id":1}]', None),
    ],
)
def test_duplicate_key_refusal_answers_with_the_request_id(
    tmp_path: Path, line: bytes, expected_id: Any
) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        s.send_raw(line + b"\n")
        reply = await s.recv()
        assert reply["error"] == {
            "code": -32600,
            "message": "repeated key in message (refused by Warden)",
        }
        assert reply["id"] == expected_id

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert session.server_saw() == []
    assert warden.asked == []


def test_recover_id_on_garbage_is_none() -> None:
    assert recover_id(b"not json") is None
    assert recover_id(b"\xff") is None
    assert recover_id(b'"text"') is None
    assert recover_id(b"[" * 100_000) is None


@pytest.mark.parametrize(
    "params",
    [None, [], {"arguments": {}}, {"name": 5}, {"name": "echo", "arguments": [1]}],
)
def test_bad_tool_call_params(tmp_path: Path, params: Any) -> None:
    async def script(s: Session) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
        if params is not None:
            message["params"] = params
        assert (await s.roundtrip(message))["error"]["code"] == -32602

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == []


def test_unknown_methods_refused_unless_allowed(tmp_path: Path) -> None:
    read = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "file:///x"}}

    async def refused(s: Session) -> None:
        assert (await s.roundtrip(read))["error"]["code"] == -32601

    session, _ = run_session(make_config(tmp_path), FakeWarden(), refused)
    assert session.server_saw() == []

    async def allowed(s: Session) -> None:
        assert (await s.roundtrip(read))["result"] == {"method": "resources/read"}

    run_session(make_config(tmp_path, allow_methods=["resources/read"]), FakeWarden(), allowed)


def test_tools_call_can_not_be_allow_listed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="always checked"):
        make_config(tmp_path, allow_methods=["tools/call"])


def test_notifications(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        # tools/call WITHOUT an id: a sloppy server might still run it. Dropped.
        s.send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "echo"}})
        s.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": "junk"})
        s.send({"no": "jsonrpc"})  # no id, no method: silently ignored
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 1, "method": "ping"}))["id"] == 1

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    methods = [m.get("method") for m in session.server_saw()]
    assert methods == ["notifications/initialized", "notifications/cancelled", "ping"]


def test_protocol_basics_pass_and_server_requests_round_trip(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}
        assert (await s.roundtrip(init))["result"]["serverInfo"]["name"] == "fake"
        tools = await s.roundtrip({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert tools["result"]["tools"][0]["name"] == "echo"
        s.send(call("ask_client", {}, request_id=2))
        server_request = await s.recv()
        assert server_request == {"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"}
        await s.recv()  # the tool result
        s.send({"jsonrpc": "2.0", "id": "srv-1", "result": {"roots": []}})
        await asyncio.sleep(0.1)
        assert s.server_saw()[-1] == {"jsonrpc": "2.0", "id": "srv-1", "result": {"roots": []}}

    # Server -> client requests are refused unless listed (tests/test_mcp_proxy_hardening.py).
    run_session(make_config(tmp_path, allow_server_requests=["roots/list"]), FakeWarden(), script)


def test_oversized_and_blank_lines(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send_raw(b"\n")
        s.send_raw(None)  # what read_line returns for an oversized line
        assert (await s.recv())["error"]["message"] == "message too large"

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == []


def test_server_exit_ends_the_session(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send(call("exit", {}))
        await asyncio.sleep(0.5)

    _, code = run_session(make_config(tmp_path), FakeWarden(), script)
    assert code == 3


def test_server_ignoring_stdin_close_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("warden.mcp_proxy.SHUTDOWN_GRACE_SECONDS", 0.3)
    config = make_config(tmp_path)
    stubborn = config.model_copy(
        update={
            "server": config.server.model_copy(
                update={"args": ("-c", "import time; time.sleep(60)")}
            )
        }
    )

    async def script(s: Session) -> None:
        pass

    started = time.monotonic()
    _, code = run_session(stubborn, FakeWarden(), script)
    assert code != 0 and time.monotonic() - started < 5


# --- End to end with a real Warden server ---------------------------------------------


@pytest.fixture
def warden_url(tmp_path: Path) -> Iterator[tuple[str, TestClient]]:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "rules": [
                    {"id": "echo-ok", "tool": "fs.echo", "effect": "allow"},
                    {
                        "id": "echo-no-etc",
                        "tool": "fs.echo",
                        "effect": "deny",
                        "when": [{"arg": "path", "op": "startswith", "value": "/etc/"}],
                    },
                    {"id": "send", "tool": "fs.send", "effect": "require_approval"},
                ]
            }
        )
    )
    app = create_app(policy, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    with live_server(app) as url:
        yield url, TestClient(app)


def test_end_to_end_with_real_warden(tmp_path: Path, warden_url: tuple[str, TestClient]) -> None:
    url, admin = warden_url
    config = make_config(tmp_path, warden_url=url, tool_prefix="fs.", agent_id="desktop")
    checker = WardenClient(url, "desktop")

    def human_approves() -> None:
        for _ in range(200):
            items = admin.get("/v1/approvals", headers={"X-Warden-Admin-Key": ADMIN_KEY}).json()
            if items:
                assert items[0]["agent_id"] == "desktop" and items[0]["tool"] == "fs.send"
                admin.post(
                    f"/v1/approvals/{items[0]['approval_id']}/approve",
                    headers={"X-Warden-Admin-Key": ADMIN_KEY},
                )
                return
            time.sleep(0.02)

    async def script(s: Session) -> None:
        ok = await s.roundtrip(call("echo", {"path": "/w/a"}, request_id=1))
        assert echoed(ok)["arguments"] == {"path": "/w/a"}
        blocked = await s.roundtrip(call("echo", {"path": "/etc/passwd"}, request_id=2))
        assert blocked["result"]["isError"] is True
        tricky = await s.roundtrip(call("echo", {"path": "/w/../etc/passwd"}, request_id=3))
        assert tricky["result"]["isError"] is True
        threading.Thread(target=human_approves, daemon=True).start()
        sent = await s.roundtrip(call("send", {"to": "x"}, request_id=4))
        assert echoed(sent)["name"] == "send"

    session, _ = run_session(config, checker, script)
    assert [c["params"]["arguments"] for c in calls_seen(session)] == [
        {"path": "/w/a"},
        {"to": "x"},
    ]


# --- Config, stdin, CLI ---------------------------------------------------------------


def test_load_config(tmp_path: Path) -> None:
    path = tmp_path / "proxy.json"
    path.write_text('{"server": {"command": "npx", "args": ["-y", "srv"]}, "agent_id": "cd"}')
    config = load_config(path)
    assert config.server.args == ("-y", "srv") and config.warden_url == "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"server": {"command": "x"}, "server": {"command": "y"}}', "duplicate key"),
        ('{"server": {"command": "x"}, "warden_url": "http://evil.com:80"}', "warden_url"),
        ('{"server": {"command": "x"}, "agnet_id": "typo"}', "agnet_id"),
        ('{"server": {"command": "x", "env": {"KEY": "s3cret-value"}}, "x": 1}', "x"),
        ("{", "server"),
    ],
)
def test_bad_config(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "proxy.json"
    path.write_text(text)
    with pytest.raises(ConfigError, match=message) as info:
        load_config(path)
    assert "s3cret" not in str(info.value)


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="can't read"):
        load_config(tmp_path / "nope.json")


def test_read_line_skips_oversized_lines() -> None:
    stream = io.BytesIO(b"a" * 50 + b"\nok\n" + b"b" * 25 + b"\n" + b"c" * 30)
    assert read_line(stream, limit=10) is None
    assert read_line(stream, limit=10) == b"ok\n"
    assert read_line(stream, limit=10) is None
    assert read_line(stream, limit=10) is None  # oversized and unterminated at EOF
    assert read_line(stream, limit=10) == b""


def test_stdin_reader_delivers_lines_then_eof() -> None:
    async def main() -> list[bytes | None]:
        read = stdin_reader(asyncio.get_running_loop(), io.BytesIO(b"one\ntwo\n"))
        return [await read(), await read(), await read()]

    assert asyncio.run(main()) == [b"one\n", b"two\n", b""]


def test_cli_needs_a_server(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["proxy"]) == 2
    assert "no MCP server given" in capsys.readouterr().err


def test_cli_rejects_remote_warden(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["proxy", "--warden-url", "http://evil.com:80", "--", "x"]) == 2
    assert "warden_url" in capsys.readouterr().err


def test_cli_bad_config_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["proxy", "--config", str(tmp_path / "none.json")]) == 2
    assert "can't read" in capsys.readouterr().err


def test_cli_builds_config_from_file_and_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "proxy.json"
    path.write_text(
        '{"server": {"command": "old", "env": {"K": "v"}}, "approval": {"timeout_seconds": 9}}'
    )
    seen: list[ProxyConfig] = []

    def fake_serve(config: ProxyConfig) -> int:
        seen.append(config)
        return 0

    monkeypatch.setattr("warden.mcp_proxy.serve_stdio", fake_serve)
    argv = ["proxy", "--config", str(path), "--agent-id", "cursor", "--tool-prefix", "gh."]
    argv += ["--approval", "error", "--", "npx", "-y", "server"]
    assert cli.main(argv) == 0
    config = seen[0]
    assert config.agent_id == "cursor" and config.tool_prefix == "gh."
    assert config.approval.mode == "error" and config.approval.timeout_seconds == 9
    assert config.server.command == "npx" and config.server.args == ("-y", "server")
    assert config.server.env == {"K": "v"}


# --- Shutdown and edge paths ----------------------------------------------------------


def test_calls_in_flight_are_answered_after_client_closes_input(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending(), pending(), ALLOW]})

    async def script(s: Session) -> None:
        s.send(call("echo", {"a": 1}))  # then the client closes stdin at once

    session, _ = run_session(make_config(tmp_path), warden, script)
    reply = session.outbox.get_nowait()
    assert echoed(reply)["arguments"] == {"a": 1}


def test_server_line_too_long_stops_the_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("warden.mcp_proxy.MAX_LINE_BYTES", 1000)
    monkeypatch.setattr("warden.mcp_proxy.SHUTDOWN_GRACE_SECONDS", 0.5)

    async def script(s: Session) -> None:
        s.send(call("big", {}))
        await asyncio.sleep(0.5)

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.outbox.empty()  # the oversized line was never passed on


def test_server_output_without_final_newline(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send(call("partial", {}))
        assert await s.recv() == {"jsonrpc": "2.0", "id": 1, "result": {}}

    run_session(make_config(tmp_path), FakeWarden(), script)


def test_odd_but_harmless_messages(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        s.send({"jsonrpc": "2.0"})  # no id, no method: ignored
        s.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}})
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 1, "method": "ping"}))["id"] == 1

    run_session(make_config(tmp_path), FakeWarden(), script)


class _BrokenWriter:
    def is_closing(self) -> bool:
        return False

    def write(self, data: bytes) -> None:
        raise ConnectionResetError

    async def drain(self) -> None:
        pass


def test_forward_to_a_dead_server_does_not_crash(tmp_path: Path) -> None:
    proxy = McpProxy(make_config(tmp_path), FakeWarden(), asyncio.Queue().get, lambda b: None)

    async def main() -> None:
        await proxy._forward({"jsonrpc": "2.0", "method": "notifications/x"})  # no server
        proxy._server_in = _BrokenWriter()  # type: ignore[assignment]
        await proxy._forward({"jsonrpc": "2.0", "method": "notifications/x"})

    asyncio.run(main())


def test_stdin_reader_stops_when_the_loop_is_gone() -> None:
    import os

    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb")

    async def main() -> None:
        stdin_reader(asyncio.get_running_loop(), stream)

    asyncio.run(main())
    os.write(write_fd, b"late line\n")
    for _ in range(100):
        if not any(t.name == "warden-proxy-stdin" for t in threading.enumerate()):
            break
        time.sleep(0.01)
    assert not any(t.name == "warden-proxy-stdin" for t in threading.enumerate())
    os.close(write_fd)
    stream.close()


def test_serve_stdio_on_real_streams(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from warden.mcp_proxy import serve_stdio

    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        call("echo", {"x": 1}, request_id=2),
    ]
    stdin = io.TextIOWrapper(io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in lines)))
    out = io.BytesIO()
    stdout = io.TextIOWrapper(out)
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    # Warden isn't running: the tool call must be denied, tools/list still answered.
    config = make_config(tmp_path, warden_url="http://127.0.0.1:9", warden_timeout_seconds=0.5)
    assert serve_stdio(config) == 0
    replies = {r["id"]: r for r in map(json.loads, out.getvalue().splitlines())}
    assert replies[1]["result"]["tools"][0]["name"] == "echo"
    assert replies[2]["result"]["isError"] is True


def test_example_proxy_config_is_valid() -> None:
    example = Path(__file__).parent.parent / "examples" / "proxy-config.json"
    config = load_config(example)
    assert config.tool_prefix == "fs." and config.approval.mode == "wait"


def test_unchecked_fields_in_tool_call_params_are_refused(tmp_path: Path) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        message = call("echo", {"path": "/ok"})
        message["params"]["argumentsOverride"] = {"path": "/etc/passwd"}
        reply = await s.roundtrip(message)
        assert reply["error"] == {"code": -32602, "message": "unexpected field in tools/call"}
        meta = call("echo", {"a": 1}, request_id=2)
        meta["params"]["_meta"] = {"progressToken": "t1"}
        assert echoed(await s.roundtrip(meta))["arguments"] == {"a": 1}

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert len(calls_seen(session)) == 1
    assert warden.asked == [("echo", {"a": 1}, None)]


def test_rate_limit_while_waiting_keeps_waiting(tmp_path: Path) -> None:
    limited = Answer(Decision.DENY, "rate limit exceeded", retry_after=0.01)
    warden = FakeWarden({"echo": [pending(), limited, limited, ALLOW]})

    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(call("echo", {})))["name"] == "echo"

    run_session(make_config(tmp_path), warden, script)


def test_approval_hint_says_to_review_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    warden = FakeWarden({"echo": [pending()]})
    config = make_config(tmp_path, approval={"mode": "error"})

    async def script(s: Session) -> None:
        await s.roundtrip(call("echo", {}))

    run_session(config, warden, script)
    err = capsys.readouterr().err
    assert err.index("/v1/approvals -H") < err.index("/approve")


def test_approval_hint_sends_the_action_hash_like_the_docs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """docs/api.md approves with {"action_hash": ...}: proof the human listed it first.
    The hint names the field but not the value, so it still has to be read from the list."""
    warden = FakeWarden({"echo": [pending()]})
    config = make_config(tmp_path, approval={"mode": "error"})

    async def script(s: Session) -> None:
        await s.roundtrip(call("echo", {}))

    run_session(config, warden, script)
    err = capsys.readouterr().err
    approve = err[err.index("/approve") :]
    assert "-H 'content-type: application/json'" in approve
    assert """-d '{"action_hash": "<action_hash from step 1>"}'""" in approve
    assert HASH not in err
