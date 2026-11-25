"""`warden proxy`: the approval hint must not name an agent the approval doesn't belong to.

With an agent token, Warden takes the agent id from the token, and the proxy's own
`agent_id` may only be a default: `approvals list --agent <that>` would show nothing."""

import asyncio
import io
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from helpers import ADMIN_KEY, live_server
from test_mcp_proxy import FakeWarden, call, make_config, pending

from warden.agents import add_agent, load_agents
from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.cli import main as cli_main
from warden.client import WardenClient
from warden.mcp_proxy import McpProxy, ProxyConfig, serve_stdio


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
            tmp_path, warden_url=url, agent_id="token-agent", approval={"mode": "error"}
        )
        assert serve_stdio(config) == 0
        approval_id = WardenClient(url, token=token).evaluate("echo", {}).approval_id
    err = capsys.readouterr().err
    assert approval_id is not None and f"approvals approve {approval_id} " in err
    assert "approvals list --warden-url" in err and "--agent" not in err
    assert token not in err


@pytest.mark.parametrize(
    ("extra", "sent"),
    [({}, None), ({"agent_id": "billing"}, "billing"), ({"agent_id": "mcp-proxy"}, "mcp-proxy")],
)
def test_with_a_token_only_a_chosen_agent_id_is_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: dict[str, str], sent: str | None
) -> None:
    made: list[WardenClient] = []

    def record(*args: Any, **kwargs: Any) -> WardenClient:
        made.append(WardenClient(*args, **kwargs))
        return made[-1]

    monkeypatch.setattr("warden.mcp_proxy.WardenClient", record)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO()))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO()))
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", "wdn_x")
    serve_stdio(make_config(tmp_path, **extra))
    monkeypatch.delenv("WARDEN_AGENT_TOKEN")
    serve_stdio(make_config(tmp_path, **extra))
    assert [c.agent_id for c in made] == [sent, sent or "mcp-proxy"]


@pytest.mark.parametrize("chosen", [False, True])
def test_cli_keeps_default_and_chosen_agent_ids_apart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chosen: bool
) -> None:
    data = {"server": {"command": "x"}, **({"agent_id": "billing"} if chosen else {})}
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps(data))
    seen: list[ProxyConfig] = []

    def serve(config: ProxyConfig) -> int:
        seen.append(config)
        return 0

    monkeypatch.setattr("warden.mcp_proxy.serve_stdio", serve)
    assert cli_main(["proxy", "--config", str(path)]) == 0
    assert ("agent_id" in seen[0].model_fields_set) is chosen
