"""examples/typescript/warden-client.ts against a real Warden and an impostor (needs Node
23.6+, which runs TypeScript directly; skipped without it)."""

import json
import os
import re
import shutil
import socket
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from helpers import ADMIN_KEY, BASIC_POLICY, live_server

from warden.agents import add_agent, load_agents
from warden.api import create_app
from warden.audit import SQLiteAuditLog

ROOT = Path(__file__).parent.parent
NODE = shutil.which("node") or "node"
FAKE_TOKEN = "wdn_" + "D" * 43
CLIENT = ROOT / "examples" / "typescript" / "warden-client.ts"


def _node_version() -> tuple[int, int] | None:
    node = shutil.which("node")
    if node is None:
        return None
    out = subprocess.run(  # noqa: S603 (node from PATH, fixed arguments)
        [node, "--version"], capture_output=True, text=True, check=False
    )
    match = re.match(r"v(\d+)\.(\d+)", out.stdout)
    return (int(match[1]), int(match[2])) if match else None


pytestmark = pytest.mark.skipif(
    (_node_version() or (0, 0)) < (23, 6), reason="needs Node 23.6+ (runs TypeScript)"
)


def run(*args: str, token: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "WARDEN_AGENT_TOKEN"}
    if token is not None:
        env["WARDEN_AGENT_TOKEN"] = token
    env["NODE_NO_WARNINGS"] = "1"
    return subprocess.run(  # noqa: S603 (our own example)
        [NODE, str(CLIENT), *args], capture_output=True, text=True, env=env, timeout=30
    )


@pytest.fixture
def warden(tmp_path: Path) -> Iterator[tuple[str, str]]:
    path = tmp_path / "agents.json"
    token = add_agent(path, "ts-agent")
    app = create_app(
        BASIC_POLICY,
        audit_log=SQLiteAuditLog(tmp_path / "a.db"),
        admin_key=ADMIN_KEY,
        agents=load_agents(path),
    )
    with live_server(app) as url:
        yield url, token


def test_typescript_client_matches_the_test_vectors() -> None:
    result = run("--vectors", str(ROOT / "docs" / "identity-test-vectors.json"))
    assert result.returncode == 0, result.stderr
    assert "all identity test vectors match" in result.stdout


def test_typescript_client_gets_proven_answers(warden: tuple[str, str]) -> None:
    url, token = warden
    allowed = json.loads(run(url, "read_file", '{"path": "/a"}', token=token).stdout)
    assert allowed["decision"] == "allow"
    denied = json.loads(run(url, "delete_file", '{"path": "/a"}', token=token).stdout)
    assert denied["decision"] == "deny"


def test_typescript_client_with_a_wrong_token_is_denied(warden: tuple[str, str]) -> None:
    url, _ = warden
    answer = json.loads(run(url, "read_file", '{"path": "/a"}', token="wdn_" + "B" * 43).stdout)
    assert answer["decision"] == "deny"
    assert json.loads(run(url, "read_file", "{}").stdout)["reason"] == "no WARDEN_AGENT_TOKEN"


def test_typescript_client_sends_nothing_secret_to_an_impostor() -> None:
    """Something else on the port answers the hello with a made-up MAC: deny, and neither
    the token nor the arguments ever reach it."""
    token, secret = "wdn_" + "C" * 43, "top-secret-path"
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    seen = bytearray()

    def impostor() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            while b"\r\n\r\n" not in seen:
                seen.extend(conn.recv(65536))
            body = json.dumps({"mac": "0" * 64}).encode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            try:
                while chunk := conn.recv(65536):
                    seen.extend(chunk)
            except OSError:
                pass

    thread = threading.Thread(target=impostor, daemon=True)
    thread.start()
    result = run(f"http://127.0.0.1:{port}", "read_file", json.dumps({"path": secret}), token=token)
    thread.join(timeout=10)
    listener.close()
    answer = json.loads(result.stdout)
    assert answer == {"decision": "deny", "reason": "Warden couldn't prove its identity"}
    assert token.encode() not in seen and secret.encode() not in seen
    assert b"/v1/hello" in seen


def test_typescript_client_refuses_a_remote_url() -> None:
    answer = json.loads(run("http://evil.example:80", "t", "{}", token=FAKE_TOKEN).stdout)
    assert answer["reason"] == "Warden must be on this machine"


def test_typescript_client_unreachable_is_a_deny() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    answer = json.loads(run(f"http://127.0.0.1:{port}", "t", "{}", token=FAKE_TOKEN).stdout)
    assert answer["decision"] == "deny" and answer["reason"].startswith("Warden unreachable")
