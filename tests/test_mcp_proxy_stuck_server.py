"""`warden proxy` and a server that stops reading its input: the client's leaving is
noticed anyway, and an approved call that hasn't left the proxy never runs.
See docs/design/proxy-stuck-server.md."""

import asyncio
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_mcp_proxy import ALLOW, FakeWarden, Session, call, make_config, pending

import warden.mcp_proxy
from warden.mcp_proxy import ProxyConfig

BIG = "x" * 2_000_000  # far more than a pipe holds
# Reads nothing until the file "go" exists, then logs every line it gets.
FROZEN = """
import os, sys, time
while not os.path.exists(sys.argv[1]):
    time.sleep(0.02)
for line in sys.stdin.buffer:
    with open(sys.argv[2], "ab") as log:
        log.write(line if line.endswith(b"\\n") else line + b"\\n")
"""


class Frozen:
    def __init__(self, tmp_path: Path) -> None:
        self.go, self.got = tmp_path / "go", tmp_path / "got"
        self.config: ProxyConfig = make_config(
            tmp_path,
            server={
                "command": sys.executable,
                "args": ["-c", FROZEN, str(self.go), str(self.got)],
                "env": {"FAKE_MCP_LOG": str(tmp_path / "unused.log")},
            },
        )

    def calls(self) -> list[dict[str, Any]]:
        """Complete tools/call messages the server could read."""
        found = []
        for line in self.got.read_bytes().splitlines() if self.got.exists() else []:
            try:
                message = json.loads(line)
            except ValueError:
                continue  # a cut-off line
            if message.get("method") == "tools/call":
                found.append(message)
        return found


async def until(condition: Callable[[], bool]) -> None:
    async with asyncio.timeout(5):
        while not condition():
            await asyncio.sleep(0.01)


def start(frozen: Frozen, warden: FakeWarden) -> tuple[Session, asyncio.Task[int]]:
    session = Session(frozen.config, warden)
    return session, asyncio.create_task(session.proxy.run())


def test_approved_call_waiting_behind_a_stuck_message_never_runs(tmp_path: Path) -> None:
    frozen = Frozen(tmp_path)
    warden = FakeWarden({"echo": [pending(), ALLOW]})

    async def main() -> None:
        session, running = start(frozen, warden)
        session.send(call("echo", {}))
        session.send({"jsonrpc": "2.0", "method": "notifications/x", "params": {"pad": BIG}})
        # Warden has allowed it, but it can't be written yet.
        await until(lambda: bool(session.proxy._write_lock._waiters))
        assert len(warden.asked) == 2 and session.proxy._held
        session.send_raw(b"")
        await until(session.proxy._client_gone.is_set)  # although the relay is stuck
        frozen.go.touch()  # the server wakes up
        await asyncio.wait_for(running, 15)

    # Slow checks, so the stuck message is written first.
    real = warden.evaluate

    def slow(tool: str, arguments: Any, approval_id: str | None = None) -> Any:
        time.sleep(0.3)
        return real(tool, arguments, approval_id)

    warden.evaluate = slow  # type: ignore[method-assign]
    asyncio.run(main())
    assert frozen.calls() == []


@pytest.mark.parametrize("cancel_first", [False, True])
def test_approved_call_half_written_when_the_client_leaves_is_cut_off(
    tmp_path: Path, cancel_first: bool
) -> None:
    frozen = Frozen(tmp_path)
    warden = FakeWarden({"echo": [pending(), ALLOW]})

    async def main() -> None:
        session, running = start(frozen, warden)
        session.send(call("echo", {"pad": BIG}))
        await until(lambda: len(warden.asked) == 2 and not session.proxy._held)
        if cancel_first:  # too late: it is being written, and must still be watched
            cancelled = {"requestId": 1}
            session.send(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": cancelled}
            )
            await asyncio.sleep(0.2)
            assert session.proxy._calls
        session.send_raw(b"")
        await until(lambda: not session.proxy._calls)
        frozen.go.touch()
        await asyncio.wait_for(running, 15)

    asyncio.run(main())
    assert frozen.calls() == []


def test_approved_call_runs_when_a_slow_server_wakes_up_and_the_client_stayed(
    tmp_path: Path,
) -> None:
    frozen = Frozen(tmp_path)
    warden = FakeWarden({"echo": [pending(), ALLOW]})

    async def main() -> None:
        session, running = start(frozen, warden)
        session.send(call("echo", {"pad": BIG}))
        await until(lambda: len(warden.asked) == 2 and not session.proxy._held)
        frozen.go.touch()
        await until(lambda: len(frozen.calls()) == 1)
        session.send_raw(b"")
        await asyncio.wait_for(running, 15)

    asyncio.run(main())
    assert len(frozen.calls()) == 1


def test_allowed_call_still_finishes_after_the_client_left(tmp_path: Path) -> None:
    frozen = Frozen(tmp_path)

    async def main() -> None:
        session, running = start(frozen, FakeWarden())
        session.send(call("echo", {"pad": BIG}))
        session.send_raw(b"")
        await until(lambda: session.proxy._client_gone.is_set() and not session.proxy._held)
        await asyncio.sleep(0.2)
        frozen.go.touch()
        await asyncio.wait_for(running, 15)

    asyncio.run(main())
    assert len(frozen.calls()) == 1


def test_proxy_ends_although_the_server_never_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(warden.mcp_proxy, "STALLED_SECONDS", 0.3)
    monkeypatch.setattr(warden.mcp_proxy, "SHUTDOWN_GRACE_SECONDS", 0.5)
    frozen = Frozen(tmp_path)

    async def main() -> Session:
        session, running = start(frozen, FakeWarden())
        session.send(call("echo", {"pad": BIG}))
        session.send(call("echo", {"pad": BIG}, request_id=2))  # waits for the first
        session.send_raw(b"")
        await asyncio.wait_for(running, 10)
        return session

    session = asyncio.run(main())
    # The second one never left the proxy, and says so.
    reply = session.outbox.get_nowait()
    assert reply["id"] == 2 and "not sent to the server" in json.dumps(reply)
    assert frozen.calls() == []


@pytest.mark.parametrize(
    ("limit", "value", "fits"), [("MAX_WAITING_LINES", 2, 2), ("MAX_WAITING_BYTES", 130, 2)]
)
def test_too_many_waiting_lines_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str, value: int, fits: int
) -> None:
    monkeypatch.setattr(warden.mcp_proxy, limit, value)
    monkeypatch.setattr(warden.mcp_proxy, "STALLED_SECONDS", 0.2)
    monkeypatch.setattr(warden.mcp_proxy, "SHUTDOWN_GRACE_SECONDS", 0.2)

    async def main() -> None:
        session = Session(Frozen(tmp_path).config, FakeWarden())
        lines: asyncio.Queue[bytes | None] = asyncio.Queue()
        for _ in range(4):
            session.send_raw(b"z" * 64 + b"\n")  # 65 bytes
        session.send_raw(b"")
        await session.proxy._read_client(lines)  # nobody handles them
        assert lines.qsize() == fits + 1  # and the end-of-input mark
        for _ in range(4 - fits):
            assert session.outbox.get_nowait()["error"]["message"] == "too many messages waiting"
        assert session.outbox.empty() and session.proxy._client_gone.is_set()

    asyncio.run(main())


def test_handled_lines_free_their_room(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(warden.mcp_proxy, "MAX_WAITING_BYTES", 200)

    async def main() -> None:
        session = Session(make_config(tmp_path), FakeWarden())
        running = asyncio.create_task(session.proxy.run())
        for i in range(20):  # far more than 200 bytes in total
            reply = await session.roundtrip({"jsonrpc": "2.0", "id": i, "method": "ping"})
            assert reply["id"] == i and "error" not in reply
        session.send_raw(b"")
        await asyncio.wait_for(running, 10)

    asyncio.run(main())


def test_nothing_small_hides_in_the_write_buffer(tmp_path: Path) -> None:
    """With asyncio's default limit, up to 64 KB count as sent while still in the proxy."""

    async def main() -> None:
        session = Session(make_config(tmp_path), FakeWarden())
        running = asyncio.create_task(session.proxy.run())
        await session.roundtrip({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        writer = session.proxy._server_in
        assert writer is not None
        assert writer.transport.get_write_buffer_limits() == (0, 0)
        session.send_raw(b"")
        await asyncio.wait_for(running, 10)

    asyncio.run(main())
