"""A lone surrogate ("\\ud800" in JSON) is not real text: it has no UTF-8 form, so the
action can't be fingerprinted. It is bad input (422), refused before evaluation, with
no ERROR log and no echo of the input. Clients refuse it too, without crashing."""

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY
from pydantic import ValidationError

from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.models import ActionRequest
from warden.sdk import NotAllowed, WardenClient, freeze, run_guarded

BODIES = [
    b'{"agent_id":"a","tool":"read_file","arguments":{"path":"\\ud800"}}',
    b'{"agent_id":"a","tool":"read_file","arguments":{"path":"/data/x\\udfff"}}',
    b'{"agent_id":"a","tool":"read_file","arguments":{"o":{"deep":["ok","\\ud800"]}}}',
    b'{"agent_id":"a","tool":"read_file","arguments":{"\\ud800":"x"}}',
    b'{"agent_id":"a","tool":"read_file","arguments":{"o":{"\\udc00":1}}}',
]


@pytest.mark.parametrize("body", BODIES)
def test_lone_surrogate_is_a_clean_422(
    tmp_path: Path, body: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    client = TestClient(create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db")))
    with caplog.at_level(logging.INFO):
        response = client.post(
            "/v1/evaluate", content=body, headers={"content-type": "application/json"}
        )
    assert response.status_code == 422
    assert response.json() == {
        "decision": "deny",
        "reason": "invalid request",
        "matched_rule": None,
        "action_hash": None,
        "approval_id": None,
    }
    assert "ud800" not in response.text and "udfff" not in response.text
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_a_valid_surrogate_pair_is_fine(tmp_path: Path) -> None:
    client = TestClient(create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db")))
    body = b'{"agent_id":"a","tool":"read_file","arguments":{"path":"/data/\\ud83d\\ude00"}}'
    response = client.post(
        "/v1/evaluate", content=body, headers={"content-type": "application/json"}
    )
    assert response.status_code == 200


def test_model_refuses_lone_surrogates_without_echoing_them() -> None:
    with pytest.raises(ValidationError) as caught:
        ActionRequest.model_validate(
            {"agent_id": "a", "tool": "t", "arguments": {"x": ["\udab1secret"]}}
        )
    # Our message never quotes the input (the API never echoes pydantic's input_value).
    assert caught.value.errors()[0]["msg"] == (
        "Value error, text must be valid Unicode (no lone surrogates)"
    )


def test_sdk_freeze_refuses_lone_surrogates() -> None:
    assert freeze({"path": "\ud800"}) is None
    assert freeze({"\ud800": 1}) is None
    assert freeze({"path": "/data/\U0001f600"}) == {"path": "/data/\U0001f600"}


def test_sdk_never_runs_or_sends_a_lone_surrogate() -> None:
    ran: list[object] = []
    # Port 9 (discard) is never asked: the SDK refuses before talking to Warden.
    client = WardenClient("http://127.0.0.1:9", "a", timeout=0.1)
    with pytest.raises(NotAllowed) as caught:
        run_guarded("read_file", {"path": "\ud800"}, ran.append, client=client)
    assert ran == []
    assert "plain JSON" in caught.value.answer.reason
