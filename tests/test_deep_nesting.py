"""JSON nested deeper than Python's parser can follow ("[[[[...]]]]" thousands deep).

json.loads raises RecursionError, which is NOT a ValueError, so code that caught only
ValueError let it escape: the API answered 500 "internal error" and one such message
ended a whole MCP proxy session. Every JSON entry point must treat it as invalid input.
"""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY
from pydantic import ValidationError
from test_mcp_proxy import FakeWarden, Session, call, calls_seen, echoed, make_config, run_session

from warden import cli
from warden.agents import AgentsError, read_agents_file
from warden.api import create_app
from warden.audit import AuditEntry, SQLiteAuditLog, verify_chain
from warden.audit_checkpoint import CheckpointError, read_checkpoints
from warden.client import _json_or_none
from warden.limits_cli import LimitsEditError, show
from warden.mcp_proxy import ConfigError, _Refused, load_config, parse_message
from warden.models import Decision
from warden.policy import parse_policy
from warden.policy_tests import PolicyTestError, load_tests
from warden.sdk import freeze

DEPTH = 30_000
DEEP_LIST = "[" * DEPTH + "]" * DEPTH


def deep_python(depth: int = DEPTH) -> list[object]:
    value: list[object] = []
    for _ in range(depth):
        value = [value]
    return value


def test_the_parser_really_raises_recursion_error() -> None:
    with pytest.raises(RecursionError):
        json.loads(DEEP_LIST)


@pytest.mark.parametrize(
    "body",
    [
        DEEP_LIST,
        '{"agent_id": "a", "tool": "read_file", "arguments": {"path": ' + DEEP_LIST + "}}",
    ],
)
def test_api_denies_without_an_internal_error(tmp_path: Path, body: str) -> None:
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/v1/evaluate", content=body, headers={"content-type": "application/json"}
    )
    assert 400 <= response.status_code < 500
    assert response.json()["decision"] == "deny"
    assert client.get("/health").status_code == 200


def test_proxy_refuses_the_message() -> None:
    with pytest.raises(_Refused):
        parse_message(DEEP_LIST.encode())


def test_proxy_session_survives_a_deep_message(tmp_path: Path) -> None:
    warden = FakeWarden()

    async def script(s: Session) -> None:
        s.send_raw(DEEP_LIST.encode() + b"\n")
        refused = await s.recv()
        assert refused["error"]["message"] == "message nested too deeply (refused by Warden)"
        # The session is still alive: the next call is checked and forwarded.
        reply = await s.roundtrip(call("echo", {"x": 1}))
        assert echoed(reply) == {"name": "echo", "arguments": {"x": 1}}

    session, _ = run_session(make_config(tmp_path), warden, script)
    assert len(calls_seen(session)) == 1


def test_sdk_refuses_to_freeze() -> None:
    assert freeze({"x": deep_python()}) is None


def test_client_treats_a_deep_answer_as_garbage() -> None:
    assert _json_or_none(DEEP_LIST.encode()) is None


def test_policy_is_invalid_not_a_crash(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    raw = '{"rules": ' + DEEP_LIST + "}"
    with pytest.raises(ValidationError):
        parse_policy(raw)
    path = tmp_path / "p.json"
    path.write_text(raw)
    assert cli.main(["check", str(path)]) == 1
    assert "ERROR" in capsys.readouterr().out


@pytest.mark.parametrize("reader", ["agents", "proxy", "limits", "checkpoints", "tests"])
def test_config_files_refuse_cleanly(tmp_path: Path, reader: str) -> None:
    path = tmp_path / "f.json"
    path.write_text(DEEP_LIST)
    errors = {
        "agents": (AgentsError, read_agents_file),
        "proxy": (ConfigError, load_config),
        "limits": (LimitsEditError, show),
        "checkpoints": (CheckpointError, read_checkpoints),
        "tests": (PolicyTestError, load_tests),
    }
    error, read = errors[reader]
    with pytest.raises(error):
        read(path)


def test_audit_verify_reports_a_deep_anchor_as_broken(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    start = datetime(2026, 6, 1, tzinfo=UTC)
    log = SQLiteAuditLog(path, retention_days=None, clock=lambda: start)
    for days_ago in (100, 0):
        when = (start - timedelta(days=days_ago)).isoformat()
        log.record(
            AuditEntry(
                timestamp=when,
                agent_id="a",
                tool="t",
                decision=Decision.ALLOW,
                reason="r",
                matched_rule=None,
                action_hash=None,
            )
        )
    log.purge_older_than(90)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE events SET chain_anchor = ? WHERE kind = 'audit_purged'", (DEEP_LIST,))
    assert not verify_chain(path).ok
