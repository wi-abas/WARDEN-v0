"""/health reports a broken policy, and Warden's own log lines are shown."""

import json
import logging
import logging.config
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from warden.api import create_app, log_config
from warden.policy import DEFAULT_POLICY_PATH


def health(policy: Path) -> tuple[int, dict]:
    response = TestClient(create_app(policy)).get("/health")
    return response.status_code, response.json()


@pytest.mark.parametrize(
    "content",
    [
        "this is not json",
        '{"rules": [{"id": "x", "tool": "y", "effect": "maybe"}]}',
        '{"rules": []}',
    ],
)
def test_no_rules_means_degraded(tmp_path: Path, content: str) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(content, encoding="utf-8")
    status, body = health(policy)
    assert status == 503
    assert body["status"] == "degraded"
    assert body["rules_loaded"] == 0


def test_missing_policy_file_means_degraded(tmp_path: Path) -> None:
    assert health(tmp_path / "nope.json")[0] == 503


def test_good_policy_is_ok() -> None:
    assert health(DEFAULT_POLICY_PATH) == (200, {"status": "ok", "rules_loaded": 3})


def test_degraded_health_does_not_leak_the_policy_path(tmp_path: Path) -> None:
    policy = tmp_path / "secret-name.json"
    assert "secret-name" not in json.dumps(health(policy)[1])


# --- Logging -------------------------------------------------------------------------


def test_log_config_shows_warden_info_lines() -> None:
    config = log_config()
    assert config["loggers"]["warden"]["level"] == "INFO"
    assert config["loggers"]["warden"]["handlers"] == ["default"]
    # Uvicorn's own loggers are kept.
    assert "uvicorn.access" in config["loggers"]


def test_log_config_does_not_change_uvicorns_default() -> None:
    import uvicorn.config

    log_config()
    assert "warden" not in uvicorn.config.LOGGING_CONFIG["loggers"]


def test_decision_lines_appear_with_the_config(capsys, tmp_path: Path) -> None:
    logging.config.dictConfig(log_config())
    try:
        client = TestClient(create_app(DEFAULT_POLICY_PATH))
        capsys.readouterr()  # drop the admin key line
        client.post(
            "/v1/evaluate",
            json={"agent_id": "a", "tool": "read_file", "arguments": {"path": "sk-live-FAKE-123"}},
        )
        err = capsys.readouterr().err
        assert "decision=allow tool=read_file rule=allow-read" in err
        assert "sk-live-FAKE-123" not in err  # arguments are never logged
    finally:
        logging.getLogger("warden").handlers.clear()
        logging.getLogger("warden").propagate = True
