"""`warden proxy`: once the client is gone, an approval must not run its tool call."""

import asyncio
import io
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue
from test_mcp_proxy import (
    ALLOW,
    FakeWarden,
    Session,
    call,
    calls_seen,
    make_config,
    pending,
    run_session,
)

from warden.client import Answer
from warden.mcp_proxy import stdin_reader

GONE = "Blocked by Warden: the client disconnected before this was approved"


def answer_text(session: Session) -> str:
    text: str = session.outbox.get_nowait()["result"]["content"][0]["text"]
    return text


def test_approval_after_the_client_left_does_not_run_the_tool(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending()]})

    async def script(s: Session) -> None:
        s.send(call("echo", {}))
        await asyncio.sleep(0.2)  # waiting for approval
        s.send_raw(b"")
        await asyncio.sleep(0.2)
        warden.answers["echo"] = [ALLOW]  # the human approves after the client left

    session, code = run_session(make_config(tmp_path), warden, script)
    assert calls_seen(session) == [] and answer_text(session) == GONE
    assert code == 0


def test_a_waiting_call_ends_at_once_when_the_client_leaves(tmp_path: Path) -> None:
    """No more polling (which could use up the approval): the session just ends."""
    warden = FakeWarden({"echo": [pending()]})
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 60, "poll_seconds": 30}
    )
    started = time.monotonic()

    async def script(s: Session) -> None:
        s.send(call("echo", {}))
        await asyncio.sleep(0.2)

    session, _ = run_session(config, warden, script)
    assert time.monotonic() - started < 8
    assert len(warden.asked) == 2 and calls_seen(session) == []


class SlowWarden(FakeWarden):
    """Takes a moment per question, so the client can leave while one is being asked."""

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        answer = super().evaluate(tool, arguments, approval_id)
        time.sleep(0.3)
        return answer


@pytest.mark.parametrize("asked", [1, 2, 3])
def test_client_leaving_during_any_question_of_an_approval_call(tmp_path: Path, asked: int) -> None:
    """Also when the approval was already used in the question being asked."""
    warden = SlowWarden({"echo": [*[pending()] * (asked - 1), ALLOW] if asked > 1 else [pending()]})

    async def script(s: Session) -> None:
        s.send(call("echo", {}))
        while len(warden.asked) < asked:
            await asyncio.sleep(0.01)

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert len(warden.asked) == asked
    assert calls_seen(session) == [] and answer_text(session) == GONE


def test_error_mode_after_the_client_left_still_answers_without_running(tmp_path: Path) -> None:
    warden = SlowWarden({"echo": [pending(), ALLOW]})

    async def script(s: Session) -> None:
        s.send(call("echo", {}))

    config = make_config(tmp_path, approval={"mode": "error"})
    session, _ = run_session(config, warden, script)
    assert calls_seen(session) == [] and answer_text(session) == GONE


def test_a_plainly_allowed_call_still_finishes_after_the_client_closes_input(
    tmp_path: Path,
) -> None:
    """No human involved: piping in one call and closing stdin keeps working."""

    async def script(s: Session) -> None:
        s.send(call("echo", {"a": 1}))

    session, _ = run_session(make_config(tmp_path), SlowWarden(), script)
    assert len(calls_seen(session)) == 1


def test_client_reader_crash_counts_as_the_client_leaving(tmp_path: Path) -> None:
    warden = FakeWarden({"echo": [pending(), pending(), pending(), ALLOW]})

    async def main() -> Session:
        session = Session(make_config(tmp_path), warden)
        session.send(call("echo", {}))

        async def read() -> bytes | None:
            if session.inbox.empty():
                await asyncio.sleep(0.02)
                raise OSError
            return await session.inbox.get()

        session.proxy.read_client = read
        session.proxy.config = session.proxy.config.model_copy(
            update={
                "approval": session.proxy.config.approval.model_copy(update={"poll_seconds": 0.2})
            }
        )
        await asyncio.wait_for(session.proxy.run(), 10)
        return session

    assert calls_seen(asyncio.run(main())) == []


class BrokenStream(io.BytesIO):
    def readline(self, *args: Any) -> bytes:
        raise OSError("gone")


def test_stdin_read_error_is_end_of_input() -> None:
    async def main() -> bytes | None:
        return await asyncio.wait_for(stdin_reader(asyncio.get_running_loop(), BrokenStream())(), 2)

    assert asyncio.run(main()) == b""
