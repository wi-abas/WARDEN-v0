"""Proxy hardening: `_meta` allow-list and server-to-client requests.

See docs/design/proxy-hardening.md. Uses the session helpers from test_mcp_proxy.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from test_mcp_proxy import FakeWarden, Session, call, calls_seen, echoed, make_config, run_session

from warden.mcp_proxy import MAX_META_INT, MAX_META_TEXT, encode

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
