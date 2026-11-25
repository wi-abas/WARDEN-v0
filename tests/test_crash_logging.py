"""A crash inside Warden never writes the exception's message or a traceback to the log:
they can hold tool arguments (Pydantic errors quote the input, for example)."""

import asyncio
import json
import logging
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY, live_server
from starlette.types import Message, Receive, Scope, Send

import warden.api
from warden.api import CrashGuard, create_app
from warden.audit import SQLiteAuditLog

CANARY = "sk-live-CANARY-5521"


def crash(*args: object, **kwargs: object) -> None:
    raise RuntimeError(f"bad argument {CANARY}")


def test_crash_on_the_real_server_logs_only_the_error_type(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    # Before the fix Starlette re-raised after the handler answered, and Uvicorn logged
    # the whole traceback, message included.
    monkeypatch.setattr(warden.api, "evaluate", crash)
    log = SQLiteAuditLog(tmp_path / "a.db")
    app = create_app(BASIC_POLICY, audit_log=log)
    body = {"agent_id": "a", "tool": "read_file", "arguments": {"path": CANARY}}
    uvicorn_logger = logging.getLogger("uvicorn.error")
    with live_server(app) as url:
        uvicorn_logger.addHandler(caplog.handler)
        try:
            request = urllib.request.Request(  # noqa: S310 - our own server
                f"{url}/v1/evaluate",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
            )
            with pytest.raises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=5)  # noqa: S310
        finally:
            uvicorn_logger.removeHandler(caplog.handler)
    answer = json.loads(caught.value.read())
    assert caught.value.code == 500
    assert (answer["decision"], answer["reason"]) == ("deny", "internal error")
    assert CANARY not in caplog.text
    assert "Traceback" not in caplog.text
    assert "unexpected error handling request: RuntimeError" in caplog.text
    app.state.warden.flush_events()
    [event] = log.recent_events()
    assert (event.http_status, event.path) == (500, "/v1/evaluate")


def test_crash_does_not_escape_the_app(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(warden.api, "evaluate", crash)
    client = TestClient(create_app(BASIC_POLICY), raise_server_exceptions=True)
    response = client.post("/v1/evaluate", json={"agent_id": "a", "tool": "read_file"})
    assert (response.status_code, response.json()["decision"]) == (500, "deny")


def test_crash_after_the_answer_started_sends_nothing_more(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sent: list[Message] = []
    rejected: list[Any] = []

    async def half_answer(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError(CANARY)

    async def receive() -> Message:
        raise AssertionError("not needed")

    async def send(message: Message) -> None:
        sent.append(message)

    guard = CrashGuard(half_answer, on_reject=lambda *args: rejected.append(args))
    asyncio.run(guard({"type": "http", "method": "POST", "path": "/"}, receive, send))
    assert [m["type"] for m in sent] == ["http.response.start"]  # no second answer
    assert len(rejected) == 1
    assert CANARY not in caplog.text


def test_non_http_traffic_passes_through() -> None:
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])
        raise RuntimeError("startup failed")

    async def receive() -> Message:
        raise AssertionError("not needed")

    async def send(message: Message) -> None:
        raise AssertionError("not needed")

    with pytest.raises(RuntimeError, match="startup failed"):  # must stop the server
        asyncio.run(CrashGuard(app)({"type": "lifespan"}, receive, send))
    assert seen == ["lifespan"]
