"""warden.sdk: the tool runs only on allow, and only with exactly what was checked."""

import asyncio
import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, live_server
from pydantic import JsonValue

from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import Answer
from warden.models import Decision
from warden.sdk import (
    ApprovalPending,
    NotAllowed,
    WardenClient,
    default_client,
    freeze,
    guard,
    run_guarded,
    run_guarded_async,
)

HASH = "b" * 64
APPROVAL = "appr-0123456789abcdef"


class FakeClient(WardenClient):
    """Scripted answers; records exactly what was asked."""

    def __init__(self, *answers: Answer, on_ask: Any = None) -> None:
        super().__init__()
        self.answers = list(answers) or [Answer(Decision.ALLOW, "ok")]
        self.asked: list[tuple[str, dict[str, JsonValue], str | None]] = []
        self.on_ask = on_ask

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        self.asked.append((tool, json.loads(json.dumps(arguments)), approval_id))
        if self.on_ask:
            self.on_ask()
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


def pending() -> Answer:
    return Answer(Decision.REQUIRE_APPROVAL, "needs a human", APPROVAL, HASH)


# --- Allow / deny ---------------------------------------------------------------------


def test_allowed_call_runs_with_checked_arguments() -> None:
    client = FakeClient()
    ran: list[dict[str, Any]] = []

    @guard(client=client)
    def send_invoice(to: str, amount: int, note: str | None = None) -> str:
        ran.append({"to": to, "amount": amount, "note": note})
        return "sent"

    assert send_invoice("acme", amount=200) == "sent"
    # Positional arguments are named and defaults are included: Warden sees the full call.
    assert client.asked == [("send_invoice", {"to": "acme", "amount": 200, "note": None}, None)]
    assert ran == [{"to": "acme", "amount": 200, "note": None}]


def test_denied_call_does_not_run() -> None:
    client = FakeClient(Answer(Decision.DENY, "no deleting"))
    ran = []

    @guard("delete_file", client=client)
    def remove(path: str) -> None:
        ran.append(path)

    with pytest.raises(NotAllowed, match="no deleting") as info:
        remove("/x")
    assert info.value.answer.decision is Decision.DENY
    assert ran == []
    assert client.asked[0][0] == "delete_file"


def test_warden_down_means_not_run() -> None:
    ran = []

    @guard(client=WardenClient("http://127.0.0.1:9", timeout=0.5))
    def read_file(path: str) -> None:
        ran.append(path)

    with pytest.raises(NotAllowed, match="Warden unreachable"):
        read_file("/a")
    assert ran == []


def test_unknown_decision_means_not_run() -> None:
    @guard(client=FakeClient(Answer(Decision.DENY, "unexpected answer from Warden")))
    def read_file(path: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed):
        read_file("/a")


# --- Checked == executed (TOCTOU) -----------------------------------------------------


def test_mutation_during_the_check_does_not_reach_the_tool() -> None:
    caller_args: dict[str, Any] = {"path": "/workspace/a.txt", "tags": ["ok"]}

    def tamper() -> None:  # e.g. another thread, while Warden is deciding
        caller_args["path"] = "/etc/passwd"
        caller_args["tags"].append("evil")

    client = FakeClient(on_ask=tamper)
    received: list[Any] = []

    @guard(client=client)
    def read_file(path: str, tags: list[str]) -> None:
        received.append((path, tags))

    read_file(**caller_args)
    assert received == [("/workspace/a.txt", ["ok"])]
    assert client.asked[0][1] == {"path": "/workspace/a.txt", "tags": ["ok"]}


def test_nested_mutation_from_another_thread() -> None:
    payload: dict[str, Any] = {"to": ["a@x.com"]}
    gate = threading.Event()
    release = threading.Event()

    def slow() -> None:
        gate.set()
        release.wait(2)

    received: list[Any] = []

    @guard("send_email", client=FakeClient(on_ask=slow))
    def send(message: dict[str, Any]) -> None:
        received.append(message)

    worker = threading.Thread(target=send, args=(payload,))
    worker.start()
    gate.wait(2)
    payload["to"].append("attacker@evil.net")  # changed while Warden is deciding
    release.set()
    worker.join(2)
    assert received == [{"to": ["a@x.com"]}]


def test_tool_gets_a_copy_not_the_callers_object() -> None:
    original: dict[str, Any] = {"items": [1, 2]}

    @guard(client=FakeClient())
    def process(data: dict[str, Any]) -> None:
        data["items"].append(3)  # the tool changing its copy doesn't touch the caller's

    process(original)
    assert original == {"items": [1, 2]}


@pytest.mark.parametrize("value", [object(), {1, 2}, float("nan"), float("inf"), b"bytes"])
def test_values_that_cant_be_checked_are_refused(value: Any) -> None:
    client = FakeClient()

    @guard(client=client)
    def tool(x: Any) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="plain JSON"):
        tool(value)
    assert client.asked == []


def test_freeze() -> None:
    assert freeze({"t": (1, 2), "d": {"k": [True, None]}}) == {
        "t": [1, 2],
        "d": {"k": [True, None]},
    }
    assert freeze({"x": object()}) is None


def test_kwargs_are_checked_by_name() -> None:
    client = FakeClient()
    got: list[dict[str, Any]] = []

    @guard(client=client)
    def search(query: str, **options: Any) -> None:
        got.append({"query": query, **options})

    search("cats", limit=5, safe=True)
    assert client.asked[0][1] == {"query": "cats", "limit": 5, "safe": True}
    assert got == [{"query": "cats", "limit": 5, "safe": True}]


# --- Approvals ------------------------------------------------------------------------


def test_approval_pending_keeps_the_rules_message() -> None:
    """The re-ask answers "waiting for a human to approve"; the rule's own message (why
    approval is needed) must not be lost from the exception."""
    rule = Answer(Decision.REQUIRE_APPROVAL, "Payments over 500 need finance", APPROVAL, HASH)
    waiting = Answer(Decision.REQUIRE_APPROVAL, "waiting for a human to approve", APPROVAL, HASH)
    client = FakeClient(rule, waiting)

    @guard(client=client)
    def pay(amount: int) -> None:
        raise AssertionError("must not run")

    with pytest.raises(ApprovalPending) as info:
        pay(900)
    assert str(info.value) == "Payments over 500 need finance (waiting for a human to approve)"
    assert info.value.answer.reason == str(info.value)
    assert info.value.approval_id == APPROVAL


def test_approval_pending_from_a_real_server_has_the_rules_reason(tmp_path: Path) -> None:
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    with live_server(app) as url:

        @guard(client=WardenClient(url, "sdk-agent"))
        def send_email(to: str) -> None:
            raise AssertionError("must not run")

        with pytest.raises(ApprovalPending) as info:
            send_email("boss@example.com")
    assert str(info.value).startswith("matched rule '")
    assert str(info.value).endswith("(waiting for a human to approve)")


def test_approval_pending_raises_with_id() -> None:
    client = FakeClient(pending())

    @guard(client=client)
    def send_email(to: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(ApprovalPending) as info:
        send_email("x@y.z")
    assert info.value.approval_id == APPROVAL
    # Asked once, then once more with the id (maybe already approved).
    assert [a[2] for a in client.asked] == [None, APPROVAL]


def test_already_approved_runs_on_retry() -> None:
    client = FakeClient(pending(), Answer(Decision.ALLOW, "approved by a human"))
    ran = []

    @guard(client=client)
    def send_email(to: str) -> None:
        ran.append(to)

    send_email("x@y.z")
    assert ran == ["x@y.z"]


def test_waits_for_approval_then_runs() -> None:
    client = FakeClient(pending(), pending(), pending(), Answer(Decision.ALLOW, "ok"))
    ran = []

    @guard(client=client, wait_for_approval=5, poll_seconds=0.01)
    def send_email(to: str) -> None:
        ran.append(to)

    send_email("x@y.z")
    assert ran == ["x@y.z"]
    assert all(a == ("send_email", {"to": "x@y.z"}, APPROVAL) for a in client.asked[1:])


def test_wait_times_out_without_running() -> None:
    @guard(client=FakeClient(pending()), wait_for_approval=0.1, poll_seconds=0.01)
    def send_email(to: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(ApprovalPending):
        send_email("x@y.z")


def test_human_says_no() -> None:
    client = FakeClient(pending(), pending(), Answer(Decision.DENY, "denied by a human"))

    @guard(client=client, wait_for_approval=5, poll_seconds=0.01)
    def send_email(to: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="denied by a human") as info:
        send_email("x@y.z")
    assert not isinstance(info.value, ApprovalPending)


def test_approval_without_id_is_deny() -> None:
    @guard(client=FakeClient(Answer(Decision.REQUIRE_APPROVAL, "x")))
    def send_email(to: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="no approval id"):
        send_email("x@y.z")


# --- Async, decorator checks, defaults ------------------------------------------------


def test_async_tools() -> None:
    client = FakeClient()

    @guard(client=client)
    async def fetch(url: str) -> str:
        return f"got {url}"

    assert asyncio.run(fetch("https://x.com/")) == "got https://x.com/"

    @guard(client=FakeClient(Answer(Decision.DENY, "no")))
    async def blocked(url: str) -> str:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed):
        asyncio.run(blocked("https://x.com/"))

    async def nope(x: Any) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="plain JSON"):
        asyncio.run(run_guarded_async("t", {"x": object()}, nope, client=client))


def test_bad_tool_names_and_signatures_fail_at_decoration() -> None:
    with pytest.raises(ValueError, match="isn't valid"):

        @guard("Send Email")
        def a() -> None: ...

    with pytest.raises(TypeError, match="can't name"):

        @guard()
        def b(*items: int) -> None: ...

    with pytest.raises(TypeError, match="can't name"):

        @guard()
        def c(x: int, /) -> None: ...


def test_run_guarded_without_decorator() -> None:
    client = FakeClient()
    assert run_guarded("add", {"a": 1, "b": 2}, lambda a, b: a + b, client=client) == 3


def test_default_client_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_URL", "http://localhost:9999")
    monkeypatch.setenv("WARDEN_AGENT_ID", "env-agent")
    client = default_client()
    assert client.url == "http://localhost:9999" and client.agent_id == "env-agent"
    monkeypatch.setenv("WARDEN_URL", "http://evil.com:80")
    with pytest.raises(ValueError, match="this machine"):
        default_client()


def test_default_client_used_when_none_given(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_URL", "http://127.0.0.1:9")

    @guard()
    def read_file(path: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="unreachable"):
        read_file("/a")


# --- End to end with a real Warden server ---------------------------------------------


@pytest.fixture
def real(tmp_path: Path) -> Iterator[tuple[WardenClient, TestClient]]:
    app = create_app(
        BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "audit.db"), admin_key=ADMIN_KEY
    )
    with live_server(app) as url:
        yield WardenClient(url, "sdk-agent"), TestClient(app)


def test_end_to_end_approval_is_single_use(real: tuple[WardenClient, TestClient]) -> None:
    client, admin = real
    headers = {"X-Warden-Admin-Key": ADMIN_KEY}
    sent = []

    @guard(client=client)
    def send_email(to: str) -> None:
        sent.append(to)

    with pytest.raises(ApprovalPending) as info:
        send_email("boss@example.com")
    approval_id = info.value.approval_id
    assert admin.post(f"/v1/approvals/{approval_id}/approve", headers=headers).status_code == 200

    # A DIFFERENT action can't use the approval.
    with pytest.raises(ApprovalPending):
        send_email("attacker@evil.net")
    send_email("boss@example.com")  # the approved one runs, once
    assert sent == ["boss@example.com"]
    with pytest.raises(ApprovalPending):  # used: needs a new approval
        send_email("boss@example.com")


def test_end_to_end_waiting_for_a_human(real: tuple[WardenClient, TestClient]) -> None:
    client, admin = real
    headers = {"X-Warden-Admin-Key": ADMIN_KEY}

    def human() -> None:
        for _ in range(200):
            items = admin.get("/v1/approvals", headers=headers).json()
            if items:
                admin.post(f"/v1/approvals/{items[0]['approval_id']}/approve", headers=headers)
                return
            time.sleep(0.02)

    threading.Thread(target=human, daemon=True).start()

    @guard(client=client, wait_for_approval=5, poll_seconds=0.02)
    def send_email(to: str) -> str:
        return f"sent to {to}"

    assert send_email("boss@example.com") == "sent to boss@example.com"

    @guard(client=client)
    def delete_file(path: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed):
        delete_file("/a")


def rate_limited() -> Answer:
    return Answer(Decision.DENY, "rate limit exceeded", retry_after=0.01)


def test_rate_limit_while_waiting_keeps_waiting() -> None:
    client = FakeClient(pending(), rate_limited(), rate_limited(), Answer(Decision.ALLOW, "ok"))
    ran = []

    @guard(client=client, wait_for_approval=5, poll_seconds=0.01)
    def send_email(to: str) -> None:
        ran.append(to)

    send_email("x@y.z")
    assert ran == ["x@y.z"]


def test_rate_limited_until_the_deadline_is_not_allowed() -> None:
    @guard(client=FakeClient(pending(), rate_limited()), wait_for_approval=0.1, poll_seconds=0.01)
    def send_email(to: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="rate limit"):
        send_email("x@y.z")


def test_rate_limited_first_question_is_not_allowed() -> None:
    @guard(client=FakeClient(rate_limited()), wait_for_approval=5, poll_seconds=0.01)
    def send_email(to: str) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="rate limit"):
        send_email("x@y.z")
