"""run_guarded_async while it waits for a human: cancelling it stops the polling (so it
can't use up the approval), and waiting calls never hold threads other calls need."""

import asyncio
import concurrent.futures
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from helpers import ADMIN_KEY, BASIC_POLICY, live_server
from pydantic import JsonValue

from warden.api import create_app
from warden.approvals import ApprovalStore
from warden.audit import SQLiteAuditLog
from warden.client import Answer
from warden.models import Decision
from warden.sdk import ApprovalPending, NotAllowed, WardenClient, run_guarded_async

APPROVAL = "appr-0123456789abcdef"


async def must_not_run(**kwargs: Any) -> None:
    raise AssertionError("must not run")


class Pending(WardenClient):
    """Every tool needs approval that never comes, except "free", which is allowed."""

    def __init__(self) -> None:
        super().__init__()
        self.asked: list[str | None] = []

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        self.asked.append(approval_id)
        if tool == "free":
            return Answer(Decision.ALLOW, "ok")
        return Answer(Decision.REQUIRE_APPROVAL, "needs a human", APPROVAL)


def test_a_cancelled_wait_leaves_the_approval_unused(tmp_path: Path) -> None:
    store = ApprovalStore()
    app = create_app(
        BASIC_POLICY,
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        approvals=store,
        admin_key=ADMIN_KEY,
    )
    ran: list[str] = []

    async def send_email(to: str) -> None:
        ran.append(to)

    with live_server(app) as url:
        client = WardenClient(url, "sdk-agent")

        async def scenario() -> None:
            call = run_guarded_async(
                "send_email",
                {"to": "x"},
                send_email,
                client=client,
                wait_for_approval=30,
                poll_seconds=0.5,
            )
            task = asyncio.create_task(call)
            while not store.pending():
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.2)  # now it is between two polls
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            [(approval, _)] = store.pending()
            store.decide(approval.approval_id, approve=True)  # the human is too late
            await asyncio.sleep(1)  # several polls' time
            assert ran == []
            # Still there: the same call, made again, runs (once).
            await run_guarded_async("send_email", {"to": "x"}, send_email, client=client)
            assert ran == ["x"]
            with pytest.raises(ApprovalPending):
                await run_guarded_async("send_email", {"to": "x"}, send_email, client=client)

        asyncio.run(scenario())
    assert ran == ["x"]


def test_no_more_questions_after_cancelling() -> None:
    client = Pending()

    async def scenario() -> None:
        call = run_guarded_async(
            "t", {}, must_not_run, client=client, wait_for_approval=30, poll_seconds=0.05
        )
        task = asyncio.create_task(call)
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.1)  # a question already on its way may still finish
        asked = len(client.asked)
        await asyncio.sleep(0.3)
        assert len(client.asked) == asked

    asyncio.run(scenario())


def test_waiting_calls_do_not_delay_an_allowed_call() -> None:
    client = Pending()

    async def free() -> str:
        return "ran"

    async def scenario() -> float:
        asyncio.get_running_loop().set_default_executor(
            concurrent.futures.ThreadPoolExecutor(max_workers=2)
        )
        waits = [
            asyncio.create_task(
                run_guarded_async(
                    "t", {"n": n}, must_not_run, client=client, wait_for_approval=1, poll_seconds=1
                )
            )
            for n in range(20)
        ]
        await asyncio.sleep(0.2)
        started = time.monotonic()
        assert await run_guarded_async("free", {}, free, client=client) == "ran"
        took = time.monotonic() - started
        results = await asyncio.gather(*waits, return_exceptions=True)
        assert all(isinstance(r, ApprovalPending) for r in results)
        return took

    assert asyncio.run(scenario()) < 0.5


def test_async_wait_then_allow_and_deny() -> None:
    for last, expected in ((Decision.ALLOW, "ran"), (Decision.DENY, None)):
        threads: set[int] = set()

        class Scripted(Pending):
            final = last

            def evaluate(
                self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
            ) -> Answer:
                threads.add(threading.get_ident())  # noqa: B023 (used in this iteration only)
                answer = super().evaluate(tool, arguments, approval_id)
                return answer if len(self.asked) < 4 else Answer(self.final, "decided")

        client = Scripted()

        async def tool() -> str:
            return "ran"

        call = run_guarded_async("t", {}, tool, client=client, wait_for_approval=5, poll_seconds=0)
        if expected:
            assert asyncio.run(call) == expected
        else:
            with pytest.raises(NotAllowed, match="decided"):
                asyncio.run(call)
        assert client.asked == [None, APPROVAL, APPROVAL, APPROVAL]
        assert threading.get_ident() not in threads  # never on the event loop's thread
