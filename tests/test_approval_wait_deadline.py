"""A wait for a human never outlasts its deadline: long pauses (Retry-After) are cut short,
one last question is asked just before the end, and nothing runs after it."""

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue
from test_mcp_proxy import ALLOW, FakeWarden, Session, call, make_config, pending, run_session

import warden.mcp_proxy as proxy_module
from warden.client import Answer, WardenClient
from warden.models import Decision
from warden.sdk import NotAllowed, run_guarded, run_guarded_async

PENDING = Answer(Decision.REQUIRE_APPROVAL, "ask", "appr-0123456789abcdef")
BUSY = Answer(Decision.DENY, "rate limit exceeded", retry_after=8.0)
YES = Answer(Decision.ALLOW, "ok")


class Timed(WardenClient):
    """Answers the first two questions with pending and rate limited, then `later`."""

    def __init__(self, later: Callable[[], Answer]) -> None:
        super().__init__()
        self.started = time.monotonic()
        self.asked: list[float] = []
        self.later = later

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        self.asked.append(time.monotonic() - self.started)
        return [PENDING, BUSY][len(self.asked) - 1] if len(self.asked) < 3 else self.later()


def run(client: WardenClient, is_async: bool) -> list[str]:
    ran: list[str] = []

    async def tool() -> None:
        ran.append("x")

    if is_async:
        asyncio.run(run_guarded_async("t", {}, tool, client=client, wait_for_approval=1))
    else:
        run_guarded("t", {}, lambda: ran.append("x"), client=client, wait_for_approval=1)
    return ran


@pytest.mark.parametrize("is_async", [False, True])
def test_last_question_is_just_before_the_deadline(is_async: bool) -> None:
    client = Timed(lambda: YES)
    assert run(client, is_async) == ["x"]
    assert len(client.asked) == 3 and 0.8 < client.asked[2] < 1


@pytest.mark.parametrize("is_async", [False, True])
def test_wait_ends_at_the_deadline(is_async: bool) -> None:
    client = Timed(lambda: BUSY)
    started = time.monotonic()
    with pytest.raises(NotAllowed, match="rate limit"):
        run(client, is_async)
    assert 1 <= time.monotonic() - started < 4
    assert len(client.asked) == 3


@pytest.mark.parametrize("is_async", [False, True])
def test_an_allow_that_arrives_after_the_deadline_doesnt_run(is_async: bool) -> None:
    def slow() -> Answer:
        time.sleep(0.5)
        return YES

    with pytest.raises(NotAllowed, match="timed out"):
        run(Timed(slow), is_async)


def test_no_question_after_an_overslept_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    """The computer slept: asking now could only waste the approval."""
    client = Timed(lambda: YES)
    real = time.sleep
    monkeypatch.setattr(time, "sleep", lambda seconds: real(seconds + 0.3))
    with pytest.raises(NotAllowed):
        run(client, False)
    assert len(client.asked) == 2


def proxy_call(tmp_path: Path, warden: FakeWarden) -> tuple[Session, dict[str, Any]]:
    config = make_config(
        tmp_path, approval={"mode": "wait", "timeout_seconds": 1, "poll_seconds": 2}
    )
    replies: list[dict[str, Any]] = []

    async def script(s: Session) -> None:
        replies.append(await s.roundtrip(call("pay", {})))

    session, _ = run_session(config, warden, script)
    return session, replies[0]


def test_proxy_asks_just_before_the_deadline(tmp_path: Path) -> None:
    started = time.monotonic()
    session, reply = proxy_call(tmp_path, FakeWarden({"pay": [pending(), BUSY, ALLOW]}))
    assert "isError" not in reply["result"] and time.monotonic() - started < 4
    assert len(session.server_saw()) == 1


def test_proxy_wait_ends_at_the_deadline(tmp_path: Path) -> None:
    session, reply = proxy_call(tmp_path, FakeWarden({"pay": [pending(), BUSY]}))
    assert "timed out" in reply["result"]["content"][0]["text"]
    assert session.server_saw() == []


def test_proxy_doesnt_run_an_allow_that_arrives_late(tmp_path: Path) -> None:
    class Late(FakeWarden):
        def evaluate(
            self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
        ) -> Answer:
            answer = super().evaluate(tool, arguments, approval_id)
            if answer.allowed:
                time.sleep(0.5)
            return answer

    session, reply = proxy_call(tmp_path, Late({"pay": [pending(), BUSY, ALLOW]}))
    assert "timed out" in reply["result"]["content"][0]["text"]
    assert session.server_saw() == []


def test_proxy_doesnt_ask_after_an_overslept_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    warden = FakeWarden({"pay": [pending(), BUSY, ALLOW]})
    monkeypatch.setattr(proxy_module, "capped_pause", lambda pause, left, total: left + 0.1)
    session, reply = proxy_call(tmp_path, warden)
    assert "timed out" in reply["result"]["content"][0]["text"]
    assert len(warden.asked) == 2 and session.server_saw() == []
