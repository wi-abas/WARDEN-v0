from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

import warden.api
from warden.api import create_app

CANARY = "sk-live-FAKE-123"  # fake value that must never be echoed back


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(BASIC_POLICY))


def body(tool: object = "read_file", **extra: object) -> dict[str, object]:
    return {"agent_id": "agent-1", "tool": tool, "arguments": {}, **extra}


def assert_deny(data: dict[str, object]) -> None:
    assert data["decision"] == "deny"
    assert data["matched_rule"] is None


# --- Health ------------------------------------------------------------------------


def test_health_reports_rules_loaded(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "rules_loaded": 3}


# --- Decisions ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "decision", "rule_id"),
    [
        ("read_file", "allow", "allow-read"),
        ("send_email", "require_approval", "approve-send"),
        ("delete_file", "deny", "block-delete"),
    ],
)
def test_evaluate_returns_decision(
    client: TestClient, tool: str, decision: str, rule_id: str
) -> None:
    response = client.post("/v1/evaluate", json=body(tool))
    assert response.status_code == 200
    assert response.json()["decision"] == decision
    assert response.json()["matched_rule"] == rule_id


def test_unknown_tool_is_denied(client: TestClient) -> None:
    response = client.post("/v1/evaluate", json=body("format_disk"))
    assert response.status_code == 200
    assert_deny(response.json())


# --- Invalid input: 422 + deny, input never echoed ----------------------------------

INVALID_BODIES = {
    "extra field": body(approved=True),
    "bad tool name": body("Delete File"),
    "tool is a number": body(123),
    "missing tool": {"agent_id": "agent-1"},
    "arguments not an object": body(arguments=["x"]),
    "empty object": {},
}


@pytest.mark.parametrize("payload", INVALID_BODIES.values(), ids=INVALID_BODIES.keys())
def test_invalid_input_is_denied(client: TestClient, payload: dict[str, object]) -> None:
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 422
    assert_deny(response.json())
    assert response.json()["reason"] == "invalid request"


def test_malformed_json_is_denied(client: TestClient) -> None:
    response = client.post(
        "/v1/evaluate", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert_deny(response.json())


def test_invalid_input_is_not_echoed_back(client: TestClient) -> None:
    payload = body("Bad Tool", arguments={"api_key": CANARY})
    response = client.post("/v1/evaluate", json=payload)
    assert response.status_code == 422
    assert CANARY not in response.text


# --- Broken policy file -------------------------------------------------------------


def test_broken_policy_file_denies_everything(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text("this is not json", encoding="utf-8")
    client = TestClient(create_app(policy))

    assert client.get("/health").status_code == 503
    assert client.get("/health").json()["rules_loaded"] == 0
    response = client.post("/v1/evaluate", json=body("read_file"))
    assert response.status_code == 200
    assert_deny(response.json())


# --- Unexpected crash: 500 + deny, no leak ------------------------------------------


def test_crash_returns_deny_without_leaking(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken_evaluate(*args: object) -> None:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(warden.api, "evaluate", broken_evaluate)
    client = TestClient(create_app(BASIC_POLICY), raise_server_exceptions=False)

    response = client.post("/v1/evaluate", json=body("read_file", arguments={"k": CANARY}))

    assert response.status_code == 500
    assert_deny(response.json())
    assert CANARY not in response.text
    assert CANARY not in caplog.text
