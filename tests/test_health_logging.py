"""/health reports a broken policy, and Warden's own log lines are shown."""

import json
import logging
import logging.config
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

from warden.api import create_app, log_config


def health(policy: Path) -> tuple[int, dict[str, Any]]:
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
    assert health(BASIC_POLICY) == (200, {"status": "ok", "rules_loaded": 3})


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


def test_decision_lines_appear_with_the_config(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    logging.config.dictConfig(log_config())
    try:
        client = TestClient(create_app(BASIC_POLICY))
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


def test_access_log_has_no_query_strings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    import http.client
    from urllib.parse import urlsplit

    from helpers import live_server

    with live_server(create_app(BASIC_POLICY)) as url:
        # After the server's own logging setup, as `warden serve` has it.
        logging.config.dictConfig(log_config())
        connection = http.client.HTTPConnection(urlsplit(url).netloc, timeout=10)
        for path in ("/health?q=sk-live-FAKE-123", "/nothing?a?b=sk-live-FAKE-123", "/health"):
            connection.request("GET", path)
            connection.getresponse().read()
        connection.close()
    logged = capsys.readouterr()
    text = logged.out + logged.err
    assert '"GET /health HTTP/1.1" 200' in text  # the request itself is still logged
    assert '"GET /nothing HTTP/1.1" 404' in text
    assert "sk-live" not in text and "?" not in text


def test_access_log_filter_leaves_unknown_records_alone() -> None:
    from warden.api import drop_query

    record = logging.LogRecord("uvicorn.access", logging.INFO, "f", 1, "%s", ("x",), None)
    assert drop_query(record) is True and record.args == ("x",)
