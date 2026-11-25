"""Per-agent tokens: agent_id comes from a secret, and approvals stay with their agent."""

import dataclasses
import json
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, live_server, shown

import warden.agents
import warden.api
from warden import cli
from warden.agents import (
    AgentEntry,
    AgentRegistry,
    AgentsError,
    add_agent,
    hash_token,
    load_agents,
    new_token,
    read_agents_file,
    remove_agent,
)
from warden.api import StartupError, create_app
from warden.approvals import ApprovalStore, Status
from warden.audit import SQLiteAuditLog
from warden.client import WardenClient
from warden.identity import proof_key
from warden.models import ActionRequest
from warden.sdk import default_client
from warden.settings import Settings, SettingsError, resolve

ADMIN = {"X-Warden-Admin-Key": ADMIN_KEY}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- Registry -------------------------------------------------------------------------


def test_tokens_identify_their_agent_only() -> None:
    a, b = new_token(), new_token()
    registry = AgentRegistry(
        (
            AgentEntry(id="a", token_sha256=hash_token(a), server_key=proof_key(a).hex()),
            AgentEntry(id="b", token_sha256=hash_token(b), server_key=proof_key(b).hex()),
        )
    )
    assert registry.identify(a) == "a" and registry.identify(b) == "b"
    assert registry.identify(new_token()) is None
    assert registry.identify(a + "x") is None  # wrong shape: refused before hashing
    assert registry.identify("") is None
    assert registry.identify_header(f"Bearer {a}") == "a"
    assert registry.identify_header(f"bearer  {a} ") == "a"
    assert registry.identify_header(None) is None
    assert registry.identify_header(f"Basic {a}") is None
    assert registry.identify_header(a) is None


def test_lookup_compares_every_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    tokens = [new_token() for _ in range(5)]
    registry = AgentRegistry(
        tuple(
            AgentEntry(id=f"a{i}", token_sha256=hash_token(t), server_key=proof_key(t).hex())
            for i, t in enumerate(tokens)
        )
    )
    calls = []
    real = secrets.compare_digest

    def counting(x: bytes, y: bytes) -> bool:
        calls.append(1)
        return bool(real(x, y))

    class FakeSecrets:
        compare_digest = staticmethod(counting)

    monkeypatch.setattr("warden.agents.secrets", FakeSecrets)
    assert registry.identify(tokens[0]) == "a0"
    assert len(calls) == 5  # no early exit when the first one matches


# --- Agents file ----------------------------------------------------------------------


def test_add_stores_only_a_hash_in_a_private_file(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    token = add_agent(path, "billing")
    assert token.startswith("wdn_") and len(token) == 47
    text = path.read_text()
    assert token not in text and hash_token(token) in text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_agents(path).identify(token) == "billing"
    second = add_agent(path, "support")
    assert second != token
    assert load_agents(path).agent_ids == ["billing", "support"]


def test_add_refuses_duplicates_and_bad_ids(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    add_agent(path, "x")
    with pytest.raises(AgentsError, match="already exists"):
        add_agent(path, "x")
    with pytest.raises(AgentsError, match="agent id"):
        add_agent(path, "bad id")


def test_remove(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    token = add_agent(path, "x")
    add_agent(path, "y")
    assert remove_agent(path, "x") is True
    assert remove_agent(path, "x") is False
    assert load_agents(path).identify(token) is None


def test_failed_write_leaves_no_temp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "agents.json"

    def broken(*args: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("warden.agents.os.replace", broken)
    with pytest.raises(OSError):
        add_agent(path, "x")
    assert list(tmp_path.iterdir()) == []


KEY_1, KEY_2 = (f'", "server_key": "{digit * 64}' for digit in "12")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"agents": [], "agents": []}', "duplicate key"),
        (
            '{"agents": [{"id": "a", "token_sha256": "' + "a" * 64 + KEY_1 + '"}, '
            '{"id": "a", "token_sha256": "' + "b" * 64 + KEY_2 + '"}]}',
            "listed twice",
        ),
        (
            '{"agents": [{"id": "a", "token_sha256": "' + "a" * 64 + KEY_1 + '"}, '
            '{"id": "b", "token_sha256": "' + "a" * 64 + KEY_2 + '"}]}',
            "share a token",
        ),
        (
            '{"agents": [{"id": "a", "token_sha256": "' + "a" * 64 + KEY_1 + '"}, '
            '{"id": "b", "token_sha256": "' + "b" * 64 + KEY_1 + '"}]}',
            "share a server_key",
        ),
        ('{"agents": [{"id": "a", "token_sha256": "wdn_plaintext"}]}', "token_sha256"),
        ('{"agents": [{"id": "a", "token": "x", "token_sha256": "' + "a" * 64 + '"}]}', "token"),
        ("not json", "agents|file|Invalid JSON"),
    ],
)
def test_invalid_agents_files(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "agents.json"
    path.write_text(text)
    with pytest.raises(AgentsError, match=message):
        read_agents_file(path)


def test_missing_agents_file(tmp_path: Path) -> None:
    with pytest.raises(AgentsError, match="can't read"):
        load_agents(tmp_path / "none.json")


# --- API ------------------------------------------------------------------------------


@pytest.fixture
def tokens(tmp_path: Path) -> dict[str, str]:
    path = tmp_path / "agents.json"
    return {name: add_agent(path, name) for name in ("agent-a", "agent-b")}


@pytest.fixture
def audit_log(tmp_path: Path) -> SQLiteAuditLog:
    return SQLiteAuditLog(tmp_path / "audit.db")


@pytest.fixture
def client(tmp_path: Path, tokens: dict[str, str], audit_log: SQLiteAuditLog) -> TestClient:
    app = create_app(
        BASIC_POLICY,
        audit_log=audit_log,
        admin_key=ADMIN_KEY,
        agents=load_agents(tmp_path / "agents.json"),
    )
    return TestClient(app)


READ = {"tool": "read_file", "arguments": {"path": "/a"}}


def test_no_token_is_401_deny(client: TestClient, audit_log: SQLiteAuditLog) -> None:
    response = client.post("/v1/evaluate", json={**READ, "agent_id": "agent-a"})
    assert response.status_code == 401
    assert response.json()["decision"] == "deny"
    assert audit_log.recent() == []  # nothing evaluated
    assert audit_log.recent_events()[0].http_status == 401


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "Bearer wdn_" + "x" * 43},
        {"Authorization": "Bearer nonsense"},
        {"Authorization": "Token wdn_" + "x" * 43},
    ],
)
def test_wrong_token_is_401(client: TestClient, header: dict[str, str]) -> None:
    assert client.post("/v1/evaluate", json=READ, headers=header).status_code == 401


def test_agent_id_comes_from_the_token(
    client: TestClient, tokens: dict[str, str], audit_log: SQLiteAuditLog
) -> None:
    response = client.post("/v1/evaluate", json=READ, headers=bearer(tokens["agent-a"]))
    assert response.json()["decision"] == "allow"
    assert audit_log.recent()[0].agent_id == "agent-a"
    # Saying who you are is fine if it matches...
    same = client.post(
        "/v1/evaluate", json={**READ, "agent_id": "agent-a"}, headers=bearer(tokens["agent-a"])
    )
    assert same.json()["decision"] == "allow"
    # ...claiming to be someone else is refused.
    spoof = client.post(
        "/v1/evaluate", json={**READ, "agent_id": "agent-b"}, headers=bearer(tokens["agent-a"])
    )
    assert spoof.status_code == 403 and spoof.json()["decision"] == "deny"


def test_approval_cant_be_used_by_another_agent(client: TestClient, tokens: dict[str, str]) -> None:
    body = {"tool": "send_email", "arguments": {"to": "boss@example.com"}}
    first = client.post("/v1/evaluate", json=body, headers=bearer(tokens["agent-a"])).json()
    approval_id = first["approval_id"]
    items = client.get("/v1/approvals", headers=ADMIN).json()
    assert items[0]["agent_id"] == "agent-a"
    assert (
        client.post(
            f"/v1/approvals/{approval_id}/approve",
            headers=ADMIN,
            json=shown(client, approval_id, ADMIN),
        ).status_code
        == 200
    )

    stolen = client.post(
        "/v1/evaluate", json={**body, "approval_id": approval_id}, headers=bearer(tokens["agent-b"])
    ).json()
    assert stolen["decision"] == "deny" and stolen["reason"] == "approval not valid"
    # The failed attempt didn't burn it: agent-a still gets its allow, once.
    mine = client.post(
        "/v1/evaluate", json={**body, "approval_id": approval_id}, headers=bearer(tokens["agent-a"])
    ).json()
    assert mine["decision"] == "allow"


def test_store_checks_the_agent_explicitly() -> None:
    store = ApprovalStore()
    action = ActionRequest(agent_id="a", tool="t", arguments={})
    approval_id = store.request(action, "c" * 64)
    assert approval_id is not None
    store.decide(approval_id, approve=True)
    # Same hash (e.g. a bug elsewhere), different agent: still refused, not burned.
    assert store.use(approval_id, "c" * 64, agent_id="b") is None
    assert store.use(approval_id, "c" * 64, agent_id="a") is Status.APPROVED


def test_open_mode_still_needs_agent_id(tmp_path: Path) -> None:
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "x.db"), admin_key=ADMIN_KEY)
    response = TestClient(app).post("/v1/evaluate", json=READ)
    assert response.status_code == 422 and response.json()["reason"] == "agent_id required"


# --- Clients --------------------------------------------------------------------------


@pytest.fixture
def live(tmp_path: Path, client: TestClient) -> Iterator[str]:
    with live_server(client.app) as url:  # type: ignore[arg-type]
        yield url


def test_client_with_a_token_and_the_wrong_agent_id_is_denied(
    live: str, tokens: dict[str, str]
) -> None:
    wrong = WardenClient(live, "agent-b", token=tokens["agent-a"])
    answer = wrong.evaluate("read_file", {"path": "/a"})
    assert not answer.allowed and "does not match" in answer.reason
    right = WardenClient(live, "agent-a", token=tokens["agent-a"])
    assert right.evaluate("read_file", {"path": "/a"}).allowed
    # Not even the plain default is sent, and an empty id isn't "none".
    empty = WardenClient(live, "", token=tokens["agent-a"])
    assert not empty.evaluate("read_file", {"path": "/a"}).allowed


def test_client_with_only_a_token(live: str, tokens: dict[str, str]) -> None:
    client = WardenClient(live, token=tokens["agent-a"])
    assert client.evaluate("read_file", {"path": "/a"}).allowed
    assert tokens["agent-a"] not in repr(client) and "<set>" in repr(client)
    assert not WardenClient(live, "agent-a").evaluate("read_file", {"path": "/a"}).allowed


def test_sdk_reads_token_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", "wdn_secret")
    assert "<set>" in repr(default_client())
    assert default_client().agent_id is None
    monkeypatch.setenv("WARDEN_AGENT_ID", "billing")
    assert default_client().agent_id == "billing"  # sent too: must match the token
    monkeypatch.delenv("WARDEN_AGENT_ID")
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", "")
    assert "token=None" in repr(default_client())


# --- Settings, startup, CLI -----------------------------------------------------------


def test_settings_agents_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    policy = tmp_path / "p.json"
    policy.write_text(BASIC_POLICY.read_text())
    path = tmp_path / "agents.json"
    add_agent(path, "x")
    settings = resolve(policy=str(policy), agents=str(path), env={})
    assert settings.agents == path and "agents=" in repr(settings)
    assert resolve(policy=str(policy), env={"WARDEN_AGENTS": str(path)}).agents == path
    with pytest.raises(SettingsError, match="agents file not found"):
        resolve(policy=str(policy), agents="nope.json", env={})
    os.chmod(path, 0o666)  # noqa: S103 (testing that this is refused)
    with pytest.raises(SettingsError, match="agents file"):
        resolve(policy=str(policy), agents=str(path), env={})


def test_main_loads_agents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: apps.append(app))
    path = tmp_path / "agents.json"
    token = add_agent(path, "x")
    base = Settings(policy=BASIC_POLICY, audit_db=tmp_path / "a.db", admin_key="k" * 32)
    warden.api.main(dataclasses.replace(base, agents=path))
    assert "1 agents with tokens" in capsys.readouterr().err
    assert apps[0].state.warden.agents.identify(token) == "x"
    warden.api.main(base)
    assert "no agent tokens" in capsys.readouterr().err
    path.write_text("{broken")
    with pytest.raises(StartupError, match="agents.json"):
        warden.api.main(dataclasses.replace(base, agents=path))


def test_cli_agent_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = str(tmp_path / "agents.json")
    assert cli.main(["agent", "list", "--agents", path]) == 0
    assert "0 agents" in capsys.readouterr().err
    assert cli.main(["agent", "add", "billing", "--agents", path]) == 0
    out = capsys.readouterr()
    token = out.out.strip()
    assert load_agents(Path(path)).identify(token) == "billing"
    assert token not in out.err  # the token is printed once, on stdout only
    assert cli.main(["agent", "add", "billing", "--agents", path]) == 2
    assert cli.main(["agent", "list", "--agents", path]) == 0
    assert capsys.readouterr().out == "billing\n"
    assert cli.main(["agent", "remove", "--agents", path]) == 2
    assert cli.main(["agent", "remove", "nobody", "--agents", path]) == 1
    assert cli.main(["agent", "remove", "billing", "--agents", path]) == 0
    assert json.loads(Path(path).read_text()) == {"agents": []}


def test_cli_agent_uses_warden_agents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Like `warden serve`: the flag, then WARDEN_AGENTS, then the default file. Ignoring
    it meant `agent remove` could leave the file the server reads untouched."""
    monkeypatch.chdir(tmp_path)
    env, flag = tmp_path / "env.json", tmp_path / "flag.json"
    monkeypatch.setenv("WARDEN_AGENTS", str(env))
    assert cli.main(["agent", "add", "billing"]) == 0
    assert str(env) in capsys.readouterr().err
    assert load_agents(env).agent_ids == ["billing"]
    assert not (tmp_path / "warden-agents.json").exists()
    assert cli.main(["agent", "add", "other", "--agents", str(flag)]) == 0
    assert (load_agents(env).agent_ids, load_agents(flag).agent_ids) == (["billing"], ["other"])
    assert cli.main(["agent", "remove", "billing"]) == 0
    assert load_agents(env).agent_ids == []
    monkeypatch.setenv("WARDEN_AGENTS", "")  # empty = not set, as everywhere else
    assert cli.main(["agent", "add", "third"]) == 0
    assert load_agents(tmp_path / "warden-agents.json").agent_ids == ["third"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
@pytest.mark.parametrize("action", [["list"], ["add", "x"], ["remove", "x"]])
def test_cli_agent_unusable_file_is_a_clear_error(
    tmp_path: Path, action: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    closed = tmp_path / "closed"
    closed.mkdir(mode=0o000)
    try:
        assert cli.main(["agent", *action, "--agents", str(closed / "a.json")]) == 2
    finally:
        closed.chmod(0o700)
    out = capsys.readouterr()
    assert out.err.startswith("warden: ") and out.out == ""  # no token for a failed add
    missing = str(tmp_path / "no-such-folder" / "a.json")
    assert cli.main(["agent", "add", "x", "--agents", missing]) == 2
    assert capsys.readouterr().out == ""
