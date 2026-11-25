"""`warden proxy`: only messages of the exact JSON-RPC shape reach the server."""

from pathlib import Path
from typing import Any

import pytest
from test_mcp_proxy import FakeWarden, Session, call, make_config, run_session

PING: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
SMUGGLED = {"name": "echo", "arguments": {"path": "/etc/passwd"}}


@pytest.mark.parametrize(
    "extra",
    [
        {"Method": "tools/call", "Params": SMUGGLED},
        {"METHOD": "tools/call"},
        {"Params": SMUGGLED},
        {"Id": 2},
        {"JSONRPC": "2.0"},
        {"result": {}},
        {"error": {}},
        {"_meta": {}},
        {"x": None},
        {"method ": "tools/call"},
        {"method\u0000": "tools/call"},
        {"mеthod": "tools/call"},  # Cyrillic letter
    ],
)
@pytest.mark.parametrize(
    "base",
    [
        PING,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {}},  # allow_methods
        call("echo", {"path": "/ok"}),
        {"jsonrpc": "2.0", "id": 1, "method": "nope"},
    ],
)
def test_request_with_an_extra_top_level_key_is_refused(
    tmp_path: Path, base: dict[str, Any], extra: dict[str, Any]
) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        # The extra keys before and after the real ones: order must not matter.
        for message in ({**base, **extra}, {**extra, **base}):
            reply = await s.roundtrip(message)
            assert reply["id"] == 1
            assert reply["error"] == {"code": -32600, "message": "unexpected key in message"}

    session, _ = run_session(
        make_config(tmp_path, allow_methods=["resources/read"]), warden, script
    )
    assert session.server_saw() == [] and warden.asked == []


@pytest.mark.parametrize(
    "extra",
    [
        {"Method": "tools/call", "Params": SMUGGLED},
        {"Id": 5, "Method": "tools/call", "Params": SMUGGLED},
        {"result": {}},
        {"x": 1},
    ],
)
@pytest.mark.parametrize("method", ["notifications/initialized", "notifications/cancelled"])
def test_notification_with_an_extra_top_level_key_is_dropped(
    tmp_path: Path, method: str, extra: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    async def script(s: Session) -> None:
        s.send({"jsonrpc": "2.0", "method": method, **extra})
        assert (await s.roundtrip(PING))["id"] == 1  # no answer to a notification

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert [m["method"] for m in session.server_saw()] == ["ping"]
    assert "unexpected key" in caplog.text and "etc/passwd" not in caplog.text


@pytest.mark.parametrize("answer", [{"result": {}}, {"error": {"code": 1, "message": "no"}}])
@pytest.mark.parametrize(
    "extra", [{"Method": "tools/call", "Params": SMUGGLED}, {"Result": {}}, {"params": SMUGGLED}]
)
def test_client_response_with_an_extra_key_is_refused(
    tmp_path: Path, answer: dict[str, Any], extra: dict[str, Any]
) -> None:
    good = {"jsonrpc": "2.0", "id": "srv-1", **answer}

    async def script(s: Session) -> None:
        reply = await s.roundtrip({**good, **extra})
        assert reply["error"]["message"] == "not a valid response"
        s.send(good)  # a normal response still passes
        assert (await s.roundtrip(PING))["id"] == 1

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == [good, PING]


@pytest.mark.parametrize("key", ["Name", "NAME", "Arguments", "ARGUMENTS", "_Meta"])
def test_case_variants_inside_tool_call_params_are_refused(tmp_path: Path, key: str) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        message = call("echo", {"path": "/ok"})
        message["params"][key] = {"path": "/etc/passwd"}
        assert (await s.roundtrip(message))["error"]["code"] == -32602

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert session.server_saw() == [] and warden.asked == []


@pytest.mark.parametrize("method", ["Tools/Call", "TOOLS/CALL", " tools/call ", "toolſ/call"])
def test_tools_call_look_alikes_can_not_be_allow_listed(tmp_path: Path, method: str) -> None:
    with pytest.raises(ValueError, match="always checked"):
        make_config(tmp_path, allow_methods=[method])


@pytest.mark.parametrize("method", ["Tools/Call", "TOOLS/CALL", "tools/call "])
def test_tools_call_look_alike_methods_are_refused(tmp_path: Path, method: str) -> None:
    async def script(s: Session) -> None:
        reply = await s.roundtrip({**call("echo", {}), "method": method})
        assert reply["error"]["code"] == -32601

    session, _ = run_session(make_config(tmp_path), FakeWarden(), script)
    assert session.server_saw() == []
