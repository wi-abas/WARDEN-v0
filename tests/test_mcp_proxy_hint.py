"""`warden proxy`: the approval hint must not name an agent the approval doesn't belong to.

With an agent token, Warden takes the agent id from the token, so the proxy's own
`agent_id` is ignored and `approvals list --agent <that>` would show nothing."""

import asyncio
import io
import json
import sys
import time
from pathlib import Path

import pytest
from helpers import ADMIN_KEY, live_server
from test_mcp_proxy import FakeWarden, call, make_config, pending

from warden.agents import add_agent, load_agents
from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import WardenClient
from warden.mcp_proxy import McpProxy, serve_stdio


def hint(tmp_path: Path, capsys: pytest.CaptureFixture[str], *, token: bool) -> str:
    warden = FakeWarden({"echo": [pending()]})
    config = make_config(tmp_path, agent_id="from-config", approval={"mode": "error"})
    proxy = McpProxy(config, warden, asyncio.Queue().get, lambda b: None, agent_from_token=token)

    async def main() -> None:
        await proxy._handle(json.dumps(call("echo", {})).encode())
        await asyncio.gather(*proxy._calls.values())

    asyncio.run(main())
    return capsys.readouterr().err


def test_hint_without_a_token_names_the_configured_agent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert "approvals list --agent from-config --warden-url http" in hint(
        tmp_path, capsys, token=False
    )


def test_hint_with_a_token_names_no_agent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    err = hint(tmp_path, capsys, token=True)
    assert "approvals list --warden-url http" in err
    assert "--agent" not in err and "from-config" not in err


def test_end_to_end_hint_with_agent_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """serve_stdio with a real token and a real Warden: the approval belongs to the
    token's agent, and the hint doesn't send the human to another one's (empty) list."""
    agents = tmp_path / "agents.json"
    token = add_agent(agents, "token-agent")
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"rules": [{"id": "r", "tool": "echo", "effect": "require_approval"}]})
    )
    app = create_app(
        policy,
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        admin_key=ADMIN_KEY,
        agents=load_agents(agents),
    )
    line = json.dumps(call("echo", {})).encode() + b"\n"

    class StaysOpen(io.BytesIO):
        """One line, then the client stays connected until the proxy has answered."""

        def readline(self, *args: object) -> bytes:
            found = super().readline()
            if not found:
                for _ in range(500):
                    if b"isError" in out.getvalue():
                        break
                    time.sleep(0.01)
            return found

    out = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(StaysOpen(line)))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out))
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", token)
    with live_server(app) as url:
        config = make_config(
            tmp_path, warden_url=url, agent_id="from-config", approval={"mode": "error"}
        )
        assert serve_stdio(config) == 0
        approval_id = WardenClient(url, token=token).evaluate("echo", {}).approval_id
    err = capsys.readouterr().err
    assert approval_id is not None and f"approvals approve {approval_id} " in err
    assert "approvals list --warden-url" in err and "--agent" not in err
    assert token not in err
