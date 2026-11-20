"""Step 5: request size limits and no secrets in logs."""

import json
import logging

import pytest
from fastapi.testclient import TestClient

import warden.api
from warden.api import MAX_BODY_BYTES, create_app
from warden.policy import DEFAULT_POLICY_PATH

CANARY = "sk-live-FAKE-123"  # fake value that must never appear in logs or responses


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(DEFAULT_POLICY_PATH), raise_server_exceptions=False)


def post_raw(client: TestClient, content: bytes, **headers: str) -> dict[str, object]:
    response = client.post(
        "/v1/evaluate",
        content=content,
        headers={"content-type": "application/json", **headers},
    )
    return {"status": response.status_code, "body": response.json()}


# --- Size limit --------------------------------------------------------------------


def test_oversized_request_is_refused(client: TestClient) -> None:
    big = {"agent_id": "a", "tool": "read_file", "arguments": {"x": "y" * MAX_BODY_BYTES}}
    result = post_raw(client, json.dumps(big).encode())
    assert result["status"] == 413
    assert result["body"]["decision"] == "deny"


def test_request_just_under_the_limit_is_accepted(client: TestClient) -> None:
    envelope = json.dumps({"agent_id": "a", "tool": "read_file", "arguments": {"x": ""}})
    padding = MAX_BODY_BYTES - len(envelope)
    payload = {"agent_id": "a", "tool": "read_file", "arguments": {"x": "y" * padding}}
    content = json.dumps(payload).encode()
    assert len(content) == MAX_BODY_BYTES
    assert post_raw(client, content)["status"] == 200


def test_lying_content_length_is_refused(client: TestClient) -> None:
    result = post_raw(client, b"{}", **{"content-length": "999999999"})
    assert result["status"] == 413


def test_chunked_body_without_length_is_refused(client: TestClient) -> None:
    def chunks():  # a generator makes the client send a chunked body with no length
        yield b'{"agent_id": "a", "tool": "read_file"}'

    response = client.post(
        "/v1/evaluate", content=chunks(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 411
    assert response.json()["decision"] == "deny"


def test_deeply_nested_json_is_denied_not_crashed(client: TestClient) -> None:
    nested = '{"a":' * 5000 + "1" + "}" * 5000
    content = ('{"agent_id": "a", "tool": "read_file", "arguments": ' + nested + "}").encode()
    assert len(content) <= MAX_BODY_BYTES
    result = post_raw(client, content)
    assert result["status"] == 422
    assert result["body"]["decision"] == "deny"


# --- No secrets in logs ------------------------------------------------------------


def secret_request(tool: str) -> dict[str, object]:
    return {"agent_id": "agent-1", "tool": tool, "arguments": {"api_key": CANARY}}


@pytest.mark.parametrize("tool", ["read_file", "send_email", "delete_file", "format_disk"])
def test_decisions_are_logged_without_arguments(
    client: TestClient, caplog: pytest.LogCaptureFixture, tool: str
) -> None:
    with caplog.at_level(logging.DEBUG):
        client.post("/v1/evaluate", json=secret_request(tool))
    assert f"tool={tool}" in caplog.text
    assert CANARY not in caplog.text


def test_invalid_request_does_not_log_secrets(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.post("/v1/evaluate", json=secret_request("Bad Tool"))
    assert response.status_code == 422
    assert CANARY not in caplog.text


def test_crash_does_not_log_secrets(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken_evaluate(*args: object) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(warden.api, "evaluate", broken_evaluate)
    client = TestClient(create_app(DEFAULT_POLICY_PATH), raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG):
        response = client.post("/v1/evaluate", json=secret_request("read_file"))
    assert response.status_code == 500
    assert CANARY not in caplog.text
