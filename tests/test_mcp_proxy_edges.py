"""`warden proxy`: exact limits, message shapes and small promises (gaps found by
mutation tests). Limits are written out as numbers on purpose, so a changed constant
fails here instead of silently moving the test along with it."""

import asyncio
import io
import json
from pathlib import Path
from typing import Any

import pytest
from test_mcp_proxy import ALLOW, FakeWarden, Session, call, make_config, pending, run_session

import warden.mcp_proxy as proxy_module
from warden.mcp_proxy import (
    ApprovalSettings,
    ConfigError,
    McpProxy,
    ProxyConfig,
    _meta_problem,
    _method_for_log,
    _safe_name,
    _server_message_kind,
    load_config,
    read_line,
)

MB = 1024 * 1024


# --- Reading lines -------------------------------------------------------------------------


def test_line_of_exactly_the_limit_is_read() -> None:
    assert read_line(io.BytesIO(b"x" * 10), limit=10) == b"x" * 10  # last line, no "\n"
    assert read_line(io.BytesIO(b"x" * 9 + b"\n"), limit=10) == b"x" * 9 + b"\n"


def test_line_one_byte_over_the_limit_is_skipped() -> None:
    stream = io.BytesIO(b"x" * 11 + b"\n" + b"next\n")
    assert read_line(stream, limit=10) is None
    assert read_line(stream, limit=10) == b"next\n"


def test_default_line_limit_is_16_mb() -> None:
    """16 MB of message, plus its newline."""
    assert read_line(io.BytesIO(b"x" * (16 * MB) + b"\n")) is not None
    assert read_line(io.BytesIO(b"x" * (16 * MB + 1) + b"\n")) is None


# --- _meta -------------------------------------------------------------------------------


def test_meta_text_and_number_limits() -> None:
    keys = ("progressToken",)
    assert _meta_problem({"progressToken": "x" * 256}, keys) is None
    assert _meta_problem({"progressToken": "x" * 257}, keys) is not None
    assert _meta_problem({"progressToken": 2**53 - 1}, keys) is None
    assert _meta_problem({"progressToken": -(2**53 - 1)}, keys) is None
    assert _meta_problem({"progressToken": 2**53}, keys) is not None


# --- Log safety ----------------------------------------------------------------------------


def test_names_in_logs_are_cut_at_64_characters() -> None:
    assert _safe_name("x" * 100) == repr("x" * 64)


def test_server_method_names_in_logs_up_to_64_characters() -> None:
    assert _method_for_log("a" * 64) == repr("a" * 64)
    assert _method_for_log("a" * 65) == "(unusual name)"


# --- Message shapes ------------------------------------------------------------------------


def test_server_request_shapes() -> None:
    base = {"jsonrpc": "2.0", "id": 1, "method": "roots/list", "params": {}}
    assert _server_message_kind(base) == "request"
    assert _server_message_kind({**base, "id": None}) is None  # null id: not a request
    assert _server_message_kind({**base, "extra": 1}) is None  # unknown key


def test_messages_that_are_not_json_rpc_get_an_error(tmp_path: Path) -> None:
    async def script(s: Session) -> None:
        for message in ({"id": 5, "result": {}}, {"method": "ping"}):
            reply = await s.roundtrip(message)
            assert reply["error"]["code"] == -32600 and reply["id"] is None
        s.send({"neither": "id nor method"})
        await s.nothing_for(0.2)

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == []


def test_a_response_with_params_is_refused_not_forwarded(tmp_path: Path) -> None:
    """A sloppy server could read {"id", "params"} as a call: it never gets one."""

    async def script(s: Session) -> None:
        reply = await s.roundtrip({"jsonrpc": "2.0", "id": 9, "params": {"name": "rm"}})
        assert reply["error"]["message"] == "not a valid response"

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == []


def test_only_cancelled_notifications_cancel_a_call(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending()] * 20 + [ALLOW]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 5, "poll_seconds": 0.01}
    )

    async def script(s: Session) -> None:
        s.send(call("echo", {"x": 1}, request_id=7))
        await asyncio.sleep(0.05)
        progress = {"progressToken": 1, "progress": 1, "requestId": 7}
        s.send({"jsonrpc": "2.0", "method": "notifications/progress", "params": progress})
        reply = await s.recv()
        assert reply["id"] == 7 and "isError" not in reply["result"]  # still answered

    run_session(config, warden, script)


# --- Limits on calls in flight -----------------------------------------------------------


def test_exactly_64_calls_in_flight(tmp_path: Path) -> None:
    warden = FakeWarden({"slow": [pending()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 1, "poll_seconds": 0.05}
    )

    async def script(s: Session) -> None:
        for i in range(64):
            s.send(call("slow", {}, request_id=i))
        await s.nothing_for(0.3)  # all 64 accepted
        reply = await s.roundtrip(call("slow", {}, request_id="65th"))
        assert reply["id"] == "65th" and "too many" in reply["result"]["content"][0]["text"]

    run_session(config, warden, script)


# --- Answers to a server that doesn't read --------------------------------------------------


class _Transport:
    def __init__(self, size: int) -> None:
        self.size = size

    def get_write_buffer_size(self) -> int:
        return self.size


class _Writer:
    def __init__(self, backlog: int) -> None:
        self.transport = _Transport(backlog)
        self.written: list[bytes] = []

    def is_closing(self) -> bool:
        return False

    def write(self, data: bytes) -> None:
        self.written.append(data)


@pytest.mark.parametrize(("backlog", "sent"), [(MB, True), (MB + 1, False)])
def test_answers_stop_past_one_mb_of_unread_backlog(
    tmp_path: Path, backlog: int, sent: bool
) -> None:
    async def noop() -> bytes | None:
        return None

    proxy = McpProxy(make_config(tmp_path), FakeWarden(), noop, lambda data: None)
    writer = _Writer(backlog)
    proxy._server_in = writer  # type: ignore[assignment]
    proxy._answer_server({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}})
    assert bool(writer.written) is sent


# --- Configuration ------------------------------------------------------------------------


def config_file(tmp_path: Path, **extra: Any) -> Path:
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps({"server": {"command": "x"}, **extra}))
    return path


def test_documented_defaults() -> None:
    settings = ApprovalSettings()
    assert (settings.mode, settings.timeout_seconds, settings.poll_seconds) == ("wait", 300, 2)
    assert ProxyConfig.model_validate({"server": {"command": "x"}}).warden_timeout_seconds == 5


@pytest.mark.parametrize(
    ("extra", "ok"),
    [
        ({"approval": {"timeout_seconds": 3600}}, True),
        ({"approval": {"timeout_seconds": 3600.5}}, False),
        ({"approval": {"poll_seconds": 60}}, True),
        ({"approval": {"poll_seconds": 60.5}}, False),
        ({"warden_timeout_seconds": 60}, True),
        ({"warden_timeout_seconds": 60.5}, False),
        ({"approval": {"timeout_seconds": "30"}}, False),  # strict: no text for numbers
        ({"warden_timeout_seconds": "5"}, False),
    ],
)
def test_config_limits(tmp_path: Path, extra: dict[str, Any], ok: bool) -> None:
    path = config_file(tmp_path, **extra)
    if ok:
        load_config(path)
    else:
        with pytest.raises(ConfigError):
            load_config(path)


def test_config_cant_be_changed_after_loading(tmp_path: Path) -> None:
    config = load_config(config_file(tmp_path))
    with pytest.raises(ValueError):
        config.agent_id = "other"  # type: ignore[misc]
    with pytest.raises(ValueError):
        config.approval.mode = "error"  # type: ignore[misc]
    with pytest.raises(ValueError):
        config.server.command = "other"  # type: ignore[misc]


# --- The agent token ----------------------------------------------------------------------


@pytest.mark.parametrize(("env", "token"), [("wdn_secret", "wdn_secret"), ("", None)])
def test_agent_token_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env: str, token: str | None
) -> None:
    seen: dict[str, Any] = {}

    class Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            seen.update(kwargs)

    def fake_run(coro: Any) -> int:
        coro.close()
        return 0

    monkeypatch.setenv("WARDEN_AGENT_TOKEN", env)
    monkeypatch.setenv("WARDEN_NO_AUTH", "1")  # "" token: run without one on purpose
    monkeypatch.setattr(proxy_module, "WardenClient", Client)
    monkeypatch.setattr("warden.mcp_proxy.asyncio.run", fake_run)
    assert proxy_module.serve_stdio(load_config(config_file(tmp_path))) == 0
    assert seen["token"] == token
