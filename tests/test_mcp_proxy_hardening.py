"""Proxy hardening: `_meta` allow-list and server-to-client requests.

See docs/design/proxy-hardening.md. Uses the session helpers from test_mcp_proxy.
"""

import asyncio
import json
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import ANY, Mock

import pytest
from helpers import ADMIN_KEY, live_server
from hypothesis import given, settings
from hypothesis import strategies as st
from test_mcp_proxy import (
    FAKE_SERVER,
    FakeWarden,
    Session,
    call,
    calls_seen,
    echoed,
    make_config,
    run_session,
)

from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import Answer
from warden.mcp_proxy import (
    MAX_ANSWER_BACKLOG,
    MAX_META_INT,
    MAX_META_TEXT,
    ConfigError,
    McpProxy,
    ProxyConfig,
    encode,
    load_config,
    parse_message,
    server_env,
)
from warden.models import Decision

# --- _meta ----------------------------------------------------------------------------


def with_meta(meta: Any, request_id: Any = 1) -> dict[str, Any]:
    message = call("echo", {"a": 1}, request_id=request_id)
    message["params"]["_meta"] = meta
    return message


@pytest.mark.parametrize("token", ["t-1", 7, 0, -MAX_META_INT, "x" * MAX_META_TEXT])
def test_meta_with_only_a_progress_token_passes_byte_for_byte(tmp_path: Path, token: Any) -> None:
    warden = FakeWarden()
    message = with_meta({"progressToken": token})

    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(message))["arguments"] == {"a": 1}

    session, _ = run_session(make_config(tmp_path), warden, script)
    raw = session.log.read_text().splitlines(keepends=True)
    assert raw == [encode(message).decode()]  # exactly what was checked, nothing else
    assert warden.asked == [("echo", {"a": 1}, None)]


def test_empty_meta_passes(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        assert echoed(await s.roundtrip(with_meta({})))["name"] == "echo"

    run_session(make_config(tmp_path), FakeWarden(), script)


@pytest.mark.parametrize(
    ("meta", "problem"),
    [
        ({"progressToken": "t", "argumentsOverride": {"path": "/etc"}}, "key that isn't allowed"),
        ({"other": 1}, "key that isn't allowed"),
        ({"progresstoken": "t"}, "key that isn't allowed"),  # case matters
        ({"progress\u0422oken": "t"}, "key that isn't allowed"),  # Cyrillic capital Te
        ({"progressToken\u200b": "t"}, "key that isn't allowed"),  # zero-width space
        ({"__proto__": {"progressToken": "t"}}, "key that isn't allowed"),
        ({"progressToken": {"nested": "x"}}, "text or whole numbers"),
        ({"progressToken": ["t"]}, "text or whole numbers"),
        ({"progressToken": True}, "text or whole numbers"),
        ({"progressToken": None}, "text or whole numbers"),
        ({"progressToken": 1.5}, "text or whole numbers"),
        ({"progressToken": MAX_META_INT + 1}, "too large"),
        ({"progressToken": -(10**30)}, "too large"),
        ({"progressToken": "x" * (MAX_META_TEXT + 1)}, "printable ASCII"),
        ({"progressToken": ""}, "printable ASCII"),
        ({"progressToken": "t\n"}, "printable ASCII"),
        ({"progressToken": "tö"}, "printable ASCII"),
        ("token", "must be an object"),
        ([{"progressToken": "t"}], "must be an object"),
        (None, "must be an object"),
    ],
)
def test_bad_meta_refuses_the_whole_call(tmp_path: Path, meta: Any, problem: str) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        reply = await s.roundtrip(with_meta(meta))
        assert reply["error"]["code"] == -32602 and problem in reply["error"]["message"]
        assert "result" not in reply

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert session.server_saw() == [] and warden.asked == []


def test_bad_meta_is_never_echoed_or_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def script(s: Session) -> None:
        reply = await s.roundtrip(with_meta({"s3cret-key": "s3cret-value"}))
        assert "s3cret" not in json.dumps(reply)

    run_session(make_config(tmp_path), FakeWarden(), script)
    assert "s3cret" not in caplog.text and "_meta" in caplog.text


def test_repeated_key_inside_meta_is_refused(tmp_path: Path) -> None:
    line = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",'
        b'"arguments":{},"_meta":{"progressToken":"a","progressToken":"b"}}}\n'
    )

    async def script(s: Session) -> None:
        s.send_raw(line)
        assert (await s.recv())["error"]["code"] == -32600

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == []


@pytest.mark.parametrize(
    "line",
    [
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\\ud800"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",'
        b'"arguments":{"p":"\\udfff"}}}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"\\ud800":1}}',
    ],
)
def test_lone_surrogate_is_refused_and_the_session_survives(tmp_path: Path, line: bytes) -> None:
    """Found in the re-audit: this used to crash the client relay and end the session."""
    warden = FakeWarden()

    async def script(s: Session) -> None:
        s.send_raw(line + b"\n")
        assert (await s.recv())["error"]["code"] == -32600
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 2, "method": "ping"}))["id"] == 2
        # A valid surrogate PAIR (an escaped emoji) is fine.
        assert echoed(await s.roundtrip(call("echo", {"e": "\U0001f600"}, request_id=3)))

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert [m.get("id") for m in session.server_saw()] == [2, 3]
    assert warden.asked == [("echo", {"e": "\U0001f600"}, None)]


@pytest.mark.parametrize(
    "line",
    [
        b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"ping"}',
        b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping"}'.encode("utf-16-le"),
    ],
)
def test_bom_or_non_utf8_message_is_refused(tmp_path: Path, line: bytes) -> None:
    """Python's json.loads(bytes) quietly accepts a BOM or UTF-16: refuse, like the API."""
    warden = FakeWarden()

    async def script(s: Session) -> None:
        s.send_raw(line + b"\n")
        error = (await s.recv())["error"]
        assert (error["code"], error["message"]) == (-32700, "invalid JSON")
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 2, "method": "ping"}))["id"] == 2

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert [m.get("id") for m in session.server_saw()] == [2]
    assert warden.asked == []


@pytest.mark.parametrize("prefix", [b"\xef\xbb\xbf", b"\xff\xfe"])
def test_parse_message_refuses_bom(prefix: bytes) -> None:
    with pytest.raises(Exception, match="invalid JSON"):
        parse_message(prefix + b'{"jsonrpc":"2.0"}')


def test_allowed_meta_keys_are_configurable(tmp_path: Path) -> None:
    config = make_config(tmp_path, allow_meta_keys=["progressToken", "io.example/trace"])

    async def script(s: Session) -> None:
        ok = with_meta({"io.example/trace": "abc", "progressToken": 3})
        assert echoed(await s.roundtrip(ok))["name"] == "echo"
        reply = await s.roundtrip(with_meta({"other": 1}, request_id=2))
        assert reply["error"]["code"] == -32602

    session, _ = run_session(config, FakeWarden(), script)
    assert len(calls_seen(session)) == 1


def test_no_meta_keys_allowed(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        reply = await s.roundtrip(with_meta({"progressToken": "t"}))
        assert reply["error"]["code"] == -32602
        assert echoed(await s.roundtrip(with_meta({}, request_id=2)))["name"] == "echo"

    run_session(make_config(tmp_path, allow_meta_keys=[]), FakeWarden(), script)


@pytest.mark.parametrize(
    "key", ["", "__proto__", "progress\u0422oken", "a b", "1abc", "x" * 65, "key\u200b", "a\n"]
)
def test_meta_key_config_is_pattern_checked(tmp_path: Path, key: str) -> None:
    with pytest.raises(ValueError, match="allow_meta_keys"):
        make_config(tmp_path, allow_meta_keys=[key])


# --- Server -> client -----------------------------------------------------------------


def ask_client(method: str, request_id: Any = 1, server_id: Any = "srv-1") -> dict[str, Any]:
    return call("ask_client", {"method": method, "id": server_id}, request_id=request_id)


def replies_to_server(session: Session) -> list[dict[str, Any]]:
    return [m for m in session.server_saw() if "method" not in m]


@pytest.mark.parametrize(
    "method", ["sampling/createMessage", "elicitation/create", "roots/list", "x/unknown"]
)
def test_server_requests_are_refused_by_default(tmp_path: Path, method: str) -> None:
    async def script(s: Session) -> None:
        reply = await s.roundtrip(ask_client(method))
        assert reply["id"] == 1 and echoed(reply)["name"] == "ask_client"  # the tool result
        await s.nothing_for(0.2)  # the server's request never reached the client

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert replies_to_server(session) == [
        {
            "jsonrpc": "2.0",
            "id": "srv-1",
            "error": {"code": -32601, "message": "request refused by Warden proxy"},
        }
    ]


def test_only_listed_server_requests_pass(tmp_path: Path) -> None:
    config = make_config(tmp_path, allow_server_requests=["roots/list"])

    async def script(s: Session) -> None:
        s.send(ask_client("roots/list", server_id=5))
        assert await s.recv() == {"jsonrpc": "2.0", "id": 5, "method": "roots/list"}
        assert (await s.recv())["id"] == 1
        s.send(ask_client("sampling/createMessage", request_id=2))
        assert (await s.recv())["id"] == 2
        await s.nothing_for(0.2)

    session, _ = run_session(config, FakeWarden(), script)
    assert [r["id"] for r in replies_to_server(session)] == ["srv-1"]  # only sampling refused


def test_server_ping_is_answered_by_the_proxy(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        assert (await s.roundtrip(ask_client("ping")))["id"] == 1
        await s.nothing_for(0.2)

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert replies_to_server(session) == [{"jsonrpc": "2.0", "id": "srv-1", "result": {}}]


GOOD_SERVER_LINES = [
    '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hi"}}',
    '{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}',
    '{"jsonrpc":"2.0","id":"x9","result":{}}',
    '{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}',
]
BAD_SERVER_LINES = [
    "not json",
    '{"jsonrpc":"2.0","id":2,"result":NaN}',
    '[{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}]',
    '"text"',
    # requests disguised as responses or notifications
    '{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","result":{}}',
    '{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","error":{}}',
    '{"jsonrpc":"2.0","method":"sampling/createMessage","params":{}}',
    '{"jsonrpc":"2.0","method":"elicitation/create"}',
    '{"jsonrpc":"2.0","id":3,"method":"notifications/x","method":"roots/list"}',
    '{"jsonrpc":"2.0","id":3,"result":{},"result":{"x":1}}',
    # wrong shapes
    '{"jsonrpc":"1.0","id":4,"method":"roots/list"}',
    '{"id":5,"method":"roots/list"}',
    '{"jsonrpc":"2.0","id":null,"method":"roots/list"}',
    '{"jsonrpc":"2.0","id":true,"method":"roots/list"}',
    '{"jsonrpc":"2.0","id":1.5,"result":{}}',
    '{"jsonrpc":"2.0","id":{"a":1},"result":{}}',
    '{"jsonrpc":"2.0","id":6,"method":"roots/list","params":[1]}',
    '{"jsonrpc":"2.0","method":"notifications/x","params":"s"}',
    '{"jsonrpc":"2.0","id":7,"result":{},"error":{}}',
    '{"jsonrpc":"2.0","id":8,"method":"roots/list","extra":1}',
    '{"jsonrpc":"2.0","method":"notifications/x","extra":1}',
    '{"jsonrpc":"2.0","method":5}',
    '{"jsonrpc":"2.0","id":9}',
    '{"jsonrpc":"2.0","id":"\\ud800","result":{}}',
]


def test_server_responses_and_notifications_pass_malformed_are_dropped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Allowing roots/list proves the disguised roots/list lines aren't let through either.
    config = make_config(tmp_path, allow_server_requests=["roots/list", "sampling/createMessage"])
    lines = GOOD_SERVER_LINES + BAD_SERVER_LINES + ['{"s3cret":1}', "   "]  # blank: skipped

    async def script(s: Session) -> None:
        s.send(call("server_says", {"lines": lines}))
        got = [await s.recv() for _ in range(len(GOOD_SERVER_LINES) + 1)]
        assert got[:-1] == [json.loads(line) for line in GOOD_SERVER_LINES]
        assert got[-1]["id"] == 1  # the tool result
        await s.nothing_for(0.2)

    session, _ = run_session(config, FakeWarden(), script)
    assert replies_to_server(session) == []  # dropped silently, never answered
    assert caplog.text.count("from the MCP server") == len(BAD_SERVER_LINES) + 1
    assert "s3cret" not in caplog.text


def test_server_cant_answer_a_call_warden_still_holds(tmp_path: Path) -> None:
    """A server response for a call the proxy hasn't forwarded yet is dropped."""
    warden = FakeWarden({"slow": [pending_answer()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 0.5, "poll_seconds": 0.01}
    )
    fake = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "done"}]}}

    async def script(s: Session) -> None:
        s.send(call("slow", {}, request_id=1))
        s.send(call("server_says", {"lines": [json.dumps(fake)]}, request_id=2))
        assert (await s.recv())["id"] == 2
        late = await s.recv()  # call 1: the human never approved
        assert late["id"] == 1 and "timed out" in late["result"]["content"][0]["text"]

    session, _ = run_session(config, warden, script)
    assert [c["params"]["name"] for c in calls_seen(session)] == ["server_says"]


def pending_answer() -> Answer:
    return Answer(Decision.REQUIRE_APPROVAL, "needs a human", "appr-0123456789abcdef", "a" * 64)


def test_initialize_hides_capabilities_the_proxy_would_refuse(tmp_path: Path) -> None:
    capabilities = {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}, "x": {}}

    def initialize(request_id: int, caps: Any) -> dict[str, Any]:
        params = {"protocolVersion": "2025-06-18", "capabilities": caps}
        return {"jsonrpc": "2.0", "id": request_id, "method": "initialize", "params": params}

    async def script(s: Session) -> None:
        await s.roundtrip(initialize(0, capabilities))
        await s.roundtrip(initialize(1, "not an object"))

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    seen = [m["params"] for m in session.server_saw()]
    assert seen == [
        {"protocolVersion": "2025-06-18", "capabilities": {"x": {}}},
        {"protocolVersion": "2025-06-18", "capabilities": "not an object"},
    ]

    async def allowed(s: Session) -> None:
        await s.roundtrip(initialize(0, capabilities))

    config = make_config(tmp_path, allow_server_requests=["roots/list"])
    session.log.unlink()
    session, _ = run_session(config, FakeWarden(), allowed)
    caps = session.server_saw()[0]["params"]["capabilities"]
    assert caps == {"roots": {"listChanged": True}, "x": {}}


@pytest.mark.parametrize(
    "method",
    ["", "Roots/list", "roots//list", "roots/list ", "/roots", "roots/", "a" * 65, "röots/list"],
)
def test_server_request_config_is_pattern_checked(tmp_path: Path, method: str) -> None:
    with pytest.raises(ValueError, match="allow_server_requests"):
        make_config(tmp_path, allow_server_requests=[method])


def test_new_config_keys_load_from_file_and_typos_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "proxy.json"
    path.write_text(
        '{"server": {"command": "x"}, "allow_server_requests": ["roots/list"],'
        ' "allow_meta_keys": ["progressToken", "io.example/trace"]}'
    )
    config = load_config(path)
    assert config.allow_server_requests == ("roots/list",)
    assert config.allow_meta_keys == ("progressToken", "io.example/trace")
    assert load_config(_write(tmp_path, '{"server": {"command": "x"}}')).allow_meta_keys == (
        "progressToken",
    )
    for typo in ("allow_server_request", "allow_meta_key"):
        with pytest.raises(ConfigError, match=typo):
            load_config(_write(tmp_path, f'{{"server": {{"command": "x"}}, "{typo}": []}}'))


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "other.json"
    path.write_text(text)
    return path


# --- Fuzzing: random server traffic ---------------------------------------------------

server_methods = st.sampled_from(
    [
        "sampling/createMessage",
        "elicitation/create",
        "roots/list",
        "roots/list ",
        "Roots/list",
        "roots/list​",
        "ping",
        "notifications/message",
        "notifications/roots/list_changed",
        "notifications",
        "",
    ]
) | st.text(max_size=12)
json_leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=6))
json_values = st.recursive(
    json_leaf,
    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=4), c, max_size=3),
    max_leaves=8,
)
server_messages = st.fixed_dictionaries(
    {},
    optional={
        "jsonrpc": st.sampled_from(["2.0", "1.0", 2.0]),
        "id": st.one_of(st.none(), st.integers(), st.text(max_size=4), st.booleans(), st.floats()),
        "method": server_methods,
        "params": json_values,
        "result": json_values,
        "error": json_values,
        "extra": json_values,
    },
)
allow_lists = st.lists(
    st.sampled_from(["roots/list", "sampling/createMessage", "elicitation/create", "ping"]),
    unique=True,
)


def run_server_lines(
    lines: list[bytes], allowed: list[str], held: tuple[str, ...] = ()
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Feed server lines to the proxy; returns (to the client, to the server)."""
    to_client: list[dict[str, Any]] = []
    to_server: list[dict[str, Any]] = []

    async def main() -> None:
        config = ProxyConfig.model_validate(
            {"server": {"command": "x"}, "allow_server_requests": allowed}, strict=False
        )
        proxy = McpProxy(config, FakeWarden(), asyncio.Queue().get, _collect(to_client))
        proxy._server_in = _ServerInput(to_server)  # type: ignore[assignment]
        proxy._held.update(held)
        for line in lines:
            await proxy._handle_server(line)

    asyncio.run(main())
    return to_client, to_server


class _ServerInput:
    """Stands in for the server's stdin: records what the proxy writes to it."""

    def __init__(self, into: list[dict[str, Any]]) -> None:
        self.transport = self
        self.write = _collect(into)

    def is_closing(self) -> bool:
        return False

    def get_write_buffer_size(self) -> int:
        return 0


def _collect(into: list[dict[str, Any]]) -> Callable[[bytes], None]:
    def write(data: bytes) -> None:
        assert data.endswith(b"\n") and data.count(b"\n") == 1
        into.append(json.loads(data))

    return write


def assert_only_allowed_reach_the_client(
    to_client: list[dict[str, Any]], to_server: list[dict[str, Any]], allowed: list[str]
) -> None:
    for message in to_client:
        assert message["jsonrpc"] == "2.0"
        if "method" in message:
            assert set(message) <= {"jsonrpc", "id", "method", "params"}
            if "id" in message:
                assert message["method"] in allowed  # a request the config allows
            else:
                assert message["method"].startswith("notifications/")
        else:
            assert set(message) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
    for reply in to_server:  # the proxy only ever answers; it never asks the server
        assert "method" not in reply and set(reply) in (
            {"jsonrpc", "id", "result"},
            {"jsonrpc", "id", "error"},
        )


@settings(max_examples=400, deadline=None)
@given(st.lists(server_messages, max_size=8), allow_lists)
def test_random_server_traffic_never_delivers_an_unallowed_request(
    batch: list[dict[str, Any]], allowed: list[str]
) -> None:
    to_client, to_server = run_server_lines([json.dumps(m).encode() for m in batch], allowed)
    assert_only_allowed_reach_the_client(to_client, to_server, allowed)
    assert len(to_client) + len(to_server) <= len(batch)


@settings(max_examples=200, deadline=None)
@given(st.lists(st.binary(max_size=40), max_size=6), allow_lists)
def test_random_server_bytes_never_deliver_an_unallowed_request(
    lines: list[bytes], allowed: list[str]
) -> None:
    to_client, to_server = run_server_lines(lines, allowed)
    assert_only_allowed_reach_the_client(to_client, to_server, allowed)


def test_server_fuzz_harness_is_not_vacuous() -> None:
    lines = [
        b'{"jsonrpc":"2.0","id":1,"method":"roots/list"}',
        b'{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"}',
        b'{"jsonrpc":"2.0","id":3,"method":"ping"}',
        b'{"jsonrpc":"2.0","method":"notifications/message"}',
        b'{"jsonrpc":"2.0","id":4,"result":{}}',
        b'{"jsonrpc":"2.0","id":5,"result":{}}',
    ]
    to_client, to_server = run_server_lines(lines, ["roots/list"], held=("5",))
    assert [m.get("id", m.get("method")) for m in to_client] == [1, "notifications/message", 4]
    assert to_server == [
        {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {"code": -32601, "message": "request refused by Warden proxy"},
        },
        {"jsonrpc": "2.0", "id": 3, "result": {}},
    ]
    assert_only_allowed_reach_the_client(to_client, to_server, ["roots/list"])


# --- Real processes: Warden server + `warden proxy` + the fake MCP server -------------


def test_real_proxy_process_refuses_a_sampling_request(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"rules": [{"id": "ask", "tool": "fs.ask_client", "effect": "allow"}]})
    )
    app = create_app(policy, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    log = tmp_path / "server.log"
    with live_server(app) as url:
        config = tmp_path / "proxy.json"
        config.write_text(
            json.dumps(
                {
                    "warden_url": url,
                    "tool_prefix": "fs.",
                    "server": {
                        "command": sys.executable,
                        "args": [str(FAKE_SERVER)],
                        "env": {"FAKE_MCP_LOG": str(log)},
                    },
                }
            )
        )
        env = {k: v for k, v in os.environ.items() if k != "WARDEN_AGENT_TOKEN"}
        env["PYTHONPATH"] = str(Path(__file__).parent.parent / "src")
        command = "import sys; from warden.cli import main; sys.exit(main(sys.argv[1:]))"
        process = subprocess.Popen(  # noqa: S603 (our own command line)
            [sys.executable, "-c", command, "proxy", "--config", str(config)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        assert process.stdin is not None and process.stdout is not None
        lines: queue.Queue[bytes] = queue.Queue()
        stdout = process.stdout

        def read_stdout() -> None:
            for line in stdout:
                lines.put(line)

        threading.Thread(target=read_stdout, daemon=True).start()

        def send(message: dict[str, Any]) -> dict[str, Any]:
            assert process.stdin is not None
            process.stdin.write(json.dumps(message).encode() + b"\n")
            process.stdin.flush()
            reply: dict[str, Any] = json.loads(lines.get(timeout=20))
            return reply

        try:
            init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}
            assert send(init)["id"] == 0
            result = send(ask_client("sampling/createMessage", server_id="srv-9"))
            assert result["id"] == 1 and echoed(result)["name"] == "ask_client"
            assert send({"jsonrpc": "2.0", "id": 2, "method": "ping"})["id"] == 2
        finally:
            process.stdin.close()
            process.wait(timeout=20)
        assert process.stderr is not None
        err = process.stderr.read()
    assert lines.empty()  # nothing else (no sampling request) reached the client
    assert "refused server request 'sampling/createMessage'" in err.decode()
    replies = [json.loads(line) for line in log.read_text().splitlines()]
    assert {"jsonrpc": "2.0", "id": "srv-9", "error": ANY} in replies


# --- Re-audit: attacks on this change -------------------------------------------------

DEEP = b"[" * 100_000 + b"]" * 100_000


def test_deep_nesting_from_the_client_is_refused_and_the_session_survives(
    tmp_path: Path,
) -> None:
    """Found in the re-audit: RecursionError crashed the client relay (session ended)."""
    deep_meta = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo",'
    deep_meta += b'"_meta":{"progressToken":' + DEEP + b"}}}"
    deep_ping = b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{"x":' + DEEP + b"}}"
    warden = FakeWarden()

    async def script(s: Session) -> None:
        for line in (deep_meta, deep_ping):
            s.send_raw(line + b"\n")
            reply = await s.recv()
            assert reply["error"]["message"] == "message nested too deeply (refused by Warden)"
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 3, "method": "ping"}))["id"] == 3

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert [m["id"] for m in session.server_saw()] == [3] and warden.asked == []


def test_deep_nesting_that_parses_but_cant_be_encoded_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def too_deep(message: Any) -> bytes:
        raise RecursionError

    monkeypatch.setattr("warden.mcp_proxy.encode", too_deep)
    with pytest.raises(Exception, match="nested too deeply"):
        parse_message(b'{"a": [[[1]]]}')


def test_deep_nesting_from_the_server_is_dropped(tmp_path: Path) -> None:
    to_client, to_server = run_server_lines(
        [
            b'{"jsonrpc":"2.0","id":1,"result":' + DEEP + b"}",
            b'{"jsonrpc":"2.0","id":2,"result":1}',
        ],
        [],
    )
    assert to_client == [{"jsonrpc": "2.0", "id": 2, "result": 1}] and to_server == []


def test_server_request_flood_is_answered_and_the_session_keeps_working(tmp_path: Path) -> None:
    flood = [
        json.dumps({"jsonrpc": "2.0", "id": i, "method": "sampling/createMessage"})
        for i in range(20_000)
    ]

    async def script(s: Session) -> None:
        s.send(call("server_says", {"lines": flood}))
        assert (await s.recv(timeout=20))["id"] == 1
        assert (await s.roundtrip({"jsonrpc": "2.0", "id": 2, "method": "ping"}))["id"] == 2

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    # Answered, unless the backlog cap kicked in (depends on the OS pipe size).
    assert 0 < len(replies_to_server(session)) <= len(flood)
    assert session.outbox.empty()  # none of them reached the client


class _StuckServer:
    """A server input nobody reads: the write buffer only grows."""

    def __init__(self, buffered: int) -> None:
        self.transport = self
        self.buffered = buffered
        self.written: list[bytes] = []

    def is_closing(self) -> bool:
        return False

    def get_write_buffer_size(self) -> int:
        return self.buffered

    def write(self, data: bytes) -> None:
        self.written.append(data)
        self.buffered += len(data)


def test_answers_to_a_server_that_stops_reading_are_capped_not_awaited(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    proxy = McpProxy(make_config(tmp_path), FakeWarden(), asyncio.Queue().get, lambda b: None)
    stuck = _StuckServer(buffered=MAX_ANSWER_BACKLOG - 10)
    proxy._server_in = stuck  # type: ignore[assignment]
    request = b'{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}'

    async def main() -> None:
        for _ in range(5):  # never blocks, even though nothing is read
            await proxy._handle_server(request)
        await proxy._handle_server(b'{"jsonrpc":"2.0","id":2,"method":"ping"}')

    asyncio.run(main())
    assert len(stuck.written) == 1  # the rest were dropped once over the cap
    assert caplog.text.count("isn't reading its input") == 1


def test_answer_to_a_dead_server_does_not_crash(tmp_path: Path) -> None:
    from test_mcp_proxy import _BrokenWriter

    class Broken(_BrokenWriter):
        transport = _StuckServer(0)

    proxy = McpProxy(make_config(tmp_path), FakeWarden(), asyncio.Queue().get, lambda b: None)
    request = b'{"jsonrpc":"2.0","id":1,"method":"roots/list"}'

    async def main() -> None:
        await proxy._handle_server(request)  # no server yet: nothing to answer
        proxy._server_in = Broken()  # type: ignore[assignment]
        await proxy._handle_server(request)

    asyncio.run(main())


def test_odd_server_method_names_are_not_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "steal/s3cret-data here"}).encode(),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "sampling/createMessage"}).encode(),
    ]
    run_server_lines(lines, [])
    assert "s3cret" not in caplog.text and "(unusual name)" in caplog.text
    assert "'sampling/createMessage'" in caplog.text


def test_server_answering_its_own_refused_request_reaches_nobody_as_a_request(
    tmp_path: Path,
) -> None:
    """The server sends a request, gets refused, then 'answers' it towards the client.
    That's just a response (the server is trusted for what it answers); it never turns
    into a request, and the proxy doesn't answer it again."""
    lines = [
        b'{"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage"}',
        b'{"jsonrpc":"2.0","id":"srv-1","result":{"content":"x"}}',
    ]
    to_client, to_server = run_server_lines(lines, [])
    assert to_client == [{"jsonrpc": "2.0", "id": "srv-1", "result": {"content": "x"}}]
    assert len(to_server) == 1 and to_server[0]["error"]["code"] == -32601


def test_server_request_reusing_a_held_client_id_is_still_refused(tmp_path: Path) -> None:
    """Ids are per direction: a server request with the id of a call Warden holds is
    refused like any other, and doesn't release or answer the held call."""
    line = b'{"jsonrpc":"2.0","id":1,"method":"elicitation/create"}'
    to_client, to_server = run_server_lines([line], [], held=("1",))
    assert to_client == [] and to_server[0]["id"] == 1 and "error" in to_server[0]


def test_server_env_drops_warden_secrets() -> None:
    inherited = {
        "PATH": "/bin",
        "WARDEN_ADMIN_KEY": "k" * 32,
        "WARDEN_AGENT_TOKEN": "wdn_x",
        "WARDEN_URL": "http://127.0.0.1:8000",
    }
    env = server_env({"API_KEY": "s"}, inherited)
    assert env == {"PATH": "/bin", "WARDEN_URL": "http://127.0.0.1:8000", "API_KEY": "s"}
    # Written into the config's "env" on purpose: kept.
    assert server_env({"WARDEN_AGENT_TOKEN": "t"}, inherited)["WARDEN_AGENT_TOKEN"] == "t"  # noqa: S105


def test_real_server_process_never_sees_the_admin_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDEN_ADMIN_KEY", "k" * 32)
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", "wdn_" + "x" * 43)
    seen = tmp_path / "env.json"
    script = f"import json, os; open({str(seen)!r}, 'w').write(json.dumps(dict(os.environ)))"
    config = ProxyConfig.model_validate(
        {"server": {"command": sys.executable, "args": ["-c", script]}}, strict=False
    )

    async def no_input() -> bytes:
        await asyncio.sleep(2)  # give the server time to write, then end the session
        return b""

    asyncio.run(McpProxy(config, Mock(), no_input, lambda data: None).run())
    env = json.loads(seen.read_text())
    assert "WARDEN_ADMIN_KEY" not in env and "WARDEN_AGENT_TOKEN" not in env
