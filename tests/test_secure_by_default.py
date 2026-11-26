"""Agent tokens are on by default (docs/design/secure-by-default.md): running without
them takes --no-auth or WARDEN_NO_AUTH=1, on the server, the SDK and the MCP proxy."""

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from helpers import BASIC_POLICY

import warden.api
from warden import cli
from warden.agents import add_agent
from warden.api import StartupError
from warden.client import no_auth_from_env
from warden.mcp_proxy import ProxyConfig, serve_stdio
from warden.sdk import default_client, guard
from warden.settings import Settings, SettingsError, resolve


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: apps.append(app))
    monkeypatch.setenv("WARDEN_ADMIN_KEY", "k" * 32)
    for var in ("WARDEN_AGENTS", "WARDEN_NO_AUTH", "WARDEN_AGENT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return apps


def serve_argv(tmp_path: Path, *extra: str) -> list[str]:
    return ["serve", "--policy", str(BASIC_POLICY), "--audit-db", str(tmp_path / "a.db"), *extra]


# --- The switch ----------------------------------------------------------------------


@pytest.mark.parametrize(("env", "expected"), [({}, False), ({"WARDEN_NO_AUTH": ""}, False)])
def test_switch_is_off_unless_set(env: dict[str, str], expected: bool) -> None:
    assert no_auth_from_env(env) is expected


def test_switch_is_on_only_for_exactly_1() -> None:
    assert no_auth_from_env({"WARDEN_NO_AUTH": "1"}) is True


@pytest.mark.parametrize("value", ["true", "0", "yes", " 1", "1 ", "on"])
def test_any_other_value_is_an_error(value: str) -> None:
    with pytest.raises(ValueError, match="WARDEN_NO_AUTH must be 1 or unset"):
        no_auth_from_env({"WARDEN_NO_AUTH": value})


# --- Server --------------------------------------------------------------------------


def test_serve_refuses_to_start_without_agents(
    tmp_path: Path, started: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(serve_argv(tmp_path)) == 2
    err = capsys.readouterr().err
    assert "agent tokens are required" in err and "warden agent add" in err
    assert "--no-auth" in err
    assert started == []


def test_serve_starts_with_no_auth_flag(
    tmp_path: Path, started: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(serve_argv(tmp_path, "--no-auth")) == 0
    assert len(started) == 1 and started[0].state.warden.agents is None
    assert "--no-auth: no agent tokens" in capsys.readouterr().err


def test_serve_starts_with_no_auth_env(
    tmp_path: Path, started: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDEN_NO_AUTH", "1")
    assert cli.main(serve_argv(tmp_path)) == 0 and len(started) == 1


def test_serve_refuses_a_bad_no_auth_value(
    tmp_path: Path,
    started: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("WARDEN_NO_AUTH", "false")
    assert cli.main(serve_argv(tmp_path)) == 2
    assert "WARDEN_NO_AUTH must be 1 or unset" in capsys.readouterr().err
    assert started == []


def test_serve_starts_with_agents(tmp_path: Path, started: list[Any]) -> None:
    agents = tmp_path / "agents.json"
    add_agent(agents, "billing")
    assert cli.main(serve_argv(tmp_path, "--agents", str(agents))) == 0
    assert started[0].state.warden.agents is not None


def test_main_with_settings_alone_refuses_too(tmp_path: Path, started: list[Any]) -> None:
    with pytest.raises(StartupError, match="agent tokens are required"):
        warden.api.main(Settings(policy=BASIC_POLICY, audit_db=tmp_path / "a.db"))
    assert started == []


def test_resolve_reads_the_flag_and_the_env() -> None:
    env = {"WARDEN_POLICY": str(BASIC_POLICY)}
    assert resolve(env=env).no_auth is False
    assert resolve(no_auth=True, env=env).no_auth is True
    assert resolve(env={**env, "WARDEN_NO_AUTH": "1"}).no_auth is True
    with pytest.raises(SettingsError, match="WARDEN_NO_AUTH"):
        resolve(env={**env, "WARDEN_NO_AUTH": "nope"})
    assert "no_auth=True" in repr(Settings(no_auth=True))


# --- SDK -----------------------------------------------------------------------------


def test_sdk_refuses_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("WARDEN_NO_AUTH", raising=False)
    with pytest.raises(ValueError, match="no WARDEN_AGENT_TOKEN.*warden agent add"):
        default_client()


def test_guarded_tool_never_runs_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("WARDEN_NO_AUTH", raising=False)
    ran: list[str] = []

    @guard()
    def send(to: str) -> None:
        ran.append(to)

    with pytest.raises(ValueError, match="no WARDEN_AGENT_TOKEN"):
        send("x")
    assert ran == []


def test_sdk_bad_switch_value_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("WARDEN_NO_AUTH", "yes")
    with pytest.raises(ValueError, match="WARDEN_NO_AUTH must be 1"):
        default_client()


def test_sdk_with_a_token_needs_no_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", "wdn_x")
    monkeypatch.delenv("WARDEN_NO_AUTH", raising=False)
    assert "<set>" in repr(default_client())


# --- MCP proxy -----------------------------------------------------------------------


def proxy_config(tmp_path: Path) -> ProxyConfig:
    return ProxyConfig.model_validate({"server": {"command": str(tmp_path / "never-started")}})


@pytest.mark.parametrize(
    ("value", "message"), [(None, "no WARDEN_AGENT_TOKEN"), ("2", "must be 1")]
)
def test_proxy_refuses_without_a_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str | None,
    message: str,
) -> None:
    monkeypatch.delenv("WARDEN_AGENT_TOKEN", raising=False)
    if value is None:
        monkeypatch.delenv("WARDEN_NO_AUTH", raising=False)
    else:
        monkeypatch.setenv("WARDEN_NO_AUTH", value)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"")))
    assert serve_stdio(proxy_config(tmp_path)) == 2
    err = capsys.readouterr().err
    assert message in err and "can't start the MCP server" not in err


def test_proxy_cli_passes_no_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def fake_serve(config: ProxyConfig, no_auth: bool = False) -> int:
        seen.append(no_auth)
        return 0

    monkeypatch.setattr("warden.mcp_proxy.serve_stdio", fake_serve)
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps({"server": {"command": "x"}}))
    assert cli.main(["proxy", "--config", str(path)]) == 0
    assert cli.main(["proxy", "--no-auth", "--config", str(path)]) == 0
    assert seen == [False, True]
