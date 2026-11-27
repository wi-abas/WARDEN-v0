"""The server's side of the proof: agents file, /v1/hello and signed answers (real sockets).

The client's side is in test_client_proof.py, the MACs themselves in test_identity.py.
"""

import asyncio
import hashlib
import http.client
import json
import logging
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, live_server
from starlette.types import Message, Receive, Scope, Send

import warden.api
from warden import cli, identity
from warden.agents import AgentsError, add_agent, load_agents, read_agents_file, remove_agent
from warden.api import AnswerSigner, CrashGuard, StartupError, create_app
from warden.audit import SQLiteAuditLog
from warden.client import WardenClient
from warden.settings import Settings, SettingsError, resolve

READ = {"tool": "read_file", "arguments": {"path": "/a"}}
NONCE = "ab" * 32


@pytest.fixture
def tokens(tmp_path: Path) -> dict[str, str]:
    return {name: add_agent(tmp_path / "agents.json", name) for name in ("agent-a", "agent-b")}


@pytest.fixture
def app(tmp_path: Path, tokens: dict[str, str]) -> FastAPI:
    return create_app(
        BASIC_POLICY,
        audit_log=SQLiteAuditLog(tmp_path / "audit.db"),
        admin_key=ADMIN_KEY,
        agents=load_agents(tmp_path / "agents.json"),
    )


@pytest.fixture
def url(app: FastAPI) -> Iterator[str]:
    with live_server(app) as base:
        yield base


class Wire:
    """One connection to the server, and what the server must have signed on it."""

    def __init__(self, url: str) -> None:
        parts = urlsplit(url)
        self.conn = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=10)
        self.conn.connect()
        self.server = identity.address(self.conn.sock.getpeername())
        self.client = identity.address(self.conn.sock.getsockname())

    def send(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        self.conn.request(method, path, body, {"content-type": "application/json", **headers})
        response = self.conn.getresponse()
        names = [name.lower() for name, _ in response.getheaders()]
        assert names.count("warden-mac") <= 1
        raw = response.read()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, raw

    def hello(
        self, key: bytes, nonce: str = NONCE, *, proven: bool = True, **headers: str
    ) -> tuple[int, Any]:
        """A hello as a real client sends it (with client_mac), or without (`proven`)."""
        data = {"key_id": identity.key_id(key), "nonce": nonce}
        if proven:
            data["client_mac"] = identity.client_hello_mac(key, nonce, self.server, self.client)
        body = json.dumps(data).encode()
        status, _, raw = self.send("POST", "/v1/hello", body, headers)
        return status, json.loads(raw)

    def expected(
        self,
        key: bytes,
        method: str,
        path: str,
        body: bytes | None,
        answer: tuple[int, dict[str, str], bytes],
        nonce: str = NONCE,
    ) -> str:
        return identity.answer_mac(
            key,
            nonce=nonce,
            server=self.server,
            client=self.client,
            method=method,
            target=path.encode(),
            request_sha256=hashlib.sha256(body or b"").hexdigest(),
            status=answer[0],
            retry_after=answer[1].get("retry-after", "").encode(),
            body=answer[2],
        )


def bearer(token: str, nonce: str = NONCE) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Warden-Nonce": nonce}


def key(token: str) -> bytes:
    return identity.proof_key(token)


ADMIN = {"X-Warden-Admin-Key": ADMIN_KEY, "Warden-Nonce": NONCE}


# --- Agents file ------------------------------------------------------------------------


def test_the_stored_key_is_the_one_the_client_derives(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    token = add_agent(path, "x")
    [entry] = read_agents_file(path).agents
    assert entry.server_key == identity.proof_key(token).hex()
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_agents(path).server_key("x") == identity.proof_key(token)
    assert entry.server_key not in repr(entry) + repr(read_agents_file(path))


def test_rotating_a_token_rotates_the_key(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    add_agent(path, "x")
    old = read_agents_file(path).agents[0].server_key
    remove_agent(path, "x")
    add_agent(path, "x")
    assert read_agents_file(path).agents[0].server_key != old


def old_entry(agent: str, digit: str = "a", **extra: Any) -> dict[str, Any]:
    return {"id": agent, "token_sha256": digit * 64, **extra}


def test_agents_file_without_server_key_doesnt_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "agents.json"
    good = old_entry("good", "c", server_key="1" * 64)
    path.write_text(json.dumps({"agents": [old_entry("billing"), good, old_entry("b2", "b")]}))
    path.chmod(0o600)
    with pytest.raises(AgentsError, match=r"no server_key for billing, b2 \(.*agent add"):
        read_agents_file(path)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: pytest.fail("started"))
    flags = ["--agents", str(path), "--audit-db", str(tmp_path / "a.db")]
    assert cli.main(["serve", "--policy", str(BASIC_POLICY), *flags]) == 2
    assert "no server_key for billing, b2" in capsys.readouterr().err
    settings = Settings(policy=BASIC_POLICY, audit_db=tmp_path / "b.db", agents=path)
    with pytest.raises(StartupError, match="no server_key"):
        warden.api.main(settings)


def test_many_agents_without_server_key_are_not_all_named(tmp_path: Path) -> None:
    path = tmp_path / "agents.json"
    for count, ending in ((20, "a19 ("), (21, "a19, ... (")):
        entries = [old_entry(f"a{i}", "abcdef"[i % 6]) for i in range(count)]
        path.write_text(json.dumps({"agents": entries}))
        with pytest.raises(AgentsError) as caught:
            read_agents_file(path)
        assert ending in str(caught.value)


@pytest.mark.parametrize("bad", ["", "1" * 63, "A" * 64, "g" * 64, "1" * 64 + "\n", 5, None])
def test_malformed_server_key_is_refused_without_showing_it(tmp_path: Path, bad: object) -> None:
    path = tmp_path / "agents.json"
    entries = [old_entry("x", server_key=bad), old_entry("y", "b")]
    path.write_text(json.dumps({"agents": entries}))
    with pytest.raises(AgentsError, match="agents.0.server_key") as caught:
        read_agents_file(path)
    if isinstance(bad, str) and len(bad) > 10:
        assert bad.strip() not in str(caught.value)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o440])
def test_agents_file_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    policy = tmp_path / "p.json"
    policy.write_text(BASIC_POLICY.read_text())
    policy.chmod(0o644)  # a policy may be readable
    path = tmp_path / "agents.json"
    add_agent(path, "x")
    assert resolve(policy=str(policy), agents=str(path), env={}).agents == path
    path.chmod(mode)
    with pytest.raises(SettingsError, match="other users can read it.*chmod 600"):
        resolve(policy=str(policy), agents=str(path), env={})


def test_permissions_are_not_checked_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("warden.settings._POSIX", False)
    path = tmp_path / "agents.json"
    add_agent(path, "x")
    path.chmod(0o644)
    assert resolve(policy=str(BASIC_POLICY), agents=str(path), env={}).agents == path


# --- /v1/hello ----------------------------------------------------------------------------


def test_hello_proves_the_key_on_this_connection(url: str, tokens: dict[str, str]) -> None:
    for secret in (*tokens.values(), ADMIN_KEY):
        wire = Wire(url)
        status, answer = wire.hello(key(secret))
        mac = identity.hello_mac(key(secret), NONCE, wire.server, wire.client)
        assert (status, answer) == (200, {"mac": mac})
        # Another nonce, another MAC; on another connection too.
        other = wire.hello(key(secret), "cd" * 32)[1]["mac"]
        assert other == identity.hello_mac(key(secret), "cd" * 32, wire.server, wire.client)
        assert Wire(url).hello(key(secret))[1]["mac"] not in (mac, other)


def test_hello_ignores_what_the_host_header_says(url: str, tokens: dict[str, str]) -> None:
    wire, k = Wire(url), key(tokens["agent-a"])
    _, answer = wire.hello(k, Host="localhost:1")
    assert answer["mac"] == identity.hello_mac(k, NONCE, wire.server, wire.client)


def test_unknown_key_id_is_a_401_deny_and_recorded(url: str, app: FastAPI) -> None:
    status, answer = Wire(url).hello(b"nobody's key")
    assert status == 401 and answer["decision"] == "deny" and "mac" not in answer
    [event] = app.state.warden.audit_log.recent_events()
    assert (event.http_status, event.path, event.reason) == (401, "/v1/hello", "unknown key_id")


def test_without_agents_only_the_admin_key_is_known(tmp_path: Path) -> None:
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    with live_server(app) as url:
        assert Wire(url).hello(key("wdn_" + "A" * 43))[0] == 401
        assert Wire(url).hello(key(ADMIN_KEY))[0] == 200


def test_key_lookup_compares_every_key(
    app: FastAPI, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import secrets

    compared: list[int] = []
    real = secrets.compare_digest

    class Counting:
        @staticmethod
        def compare_digest(a: Any, b: Any) -> bool:
            compared.append(1)
            return bool(real(a, b))

    monkeypatch.setattr("warden.agents.secrets", Counting)
    registry = app.state.warden.agents
    for name, token in tokens.items():
        compared.clear()
        wanted = identity.key_id(key(token))
        assert registry.find_key(wanted) == (name, key(token)) and len(compared) == 2
    compared.clear()
    assert registry.find_key("0" * 32) is None and len(compared) == 2


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b"{}",
        b'{"key_id": "%s"}' % (b"a" * 32),
        b'{"nonce": "%s"}' % (b"a" * 64),
        b'{"key_id": "%s", "nonce": "%s", "x": 1}' % (b"a" * 32, b"a" * 64),
        b'{"key_id": "%s", "key_id": "%s", "nonce": "%s"}' % (b"a" * 32, b"b" * 32, b"a" * 64),
        b'{"key_id": "%s", "nonce": "%s"}' % (b"A" * 32, b"a" * 64),
        b'{"key_id": "%s", "nonce": "%s"}' % (b"a" * 31, b"a" * 64),
        b'{"key_id": "%s", "nonce": "%s"}' % (b"a" * 32, b"a" * 63),
        b'{"key_id": "%s", "nonce": "%s\\n"}' % (b"a" * 32, b"a" * 64),
        b'{"key_id": "%s", "nonce": 5}' % (b"a" * 32),
    ],
)
def test_malformed_hellos(url: str, body: bytes) -> None:
    status, headers, raw = Wire(url).send("POST", "/v1/hello", body, {})
    assert status == 422 and json.loads(raw)["decision"] == "deny"
    assert "warden-mac" not in headers


def test_hello_has_the_usual_checks(url: str, tokens: dict[str, str]) -> None:
    k = key(tokens["agent-a"])
    assert Wire(url).hello(k, Host="evil.example.com")[0] == 400
    assert Wire(url).send("POST", "/v1/hello", b" " * (64 * 1024 + 1), {})[0] == 413
    assert Wire(url).send("GET", "/v1/hello", None, {})[0] == 405
    body = json.dumps({"key_id": identity.key_id(k), "nonce": NONCE}).encode()
    te = {"Transfer-Encoding": "chunked"}
    wire = Wire(url)
    wire.conn.request("POST", "/v1/hello", iter([body]), te, encode_chunked=True)
    assert wire.conn.getresponse().status == 411


@pytest.mark.parametrize("name", ["X-Forwarded-For", "x-forwarded-for"])
def test_the_client_address_cant_be_forged(url: str, tokens: dict[str, str], name: str) -> None:
    """Uvicorn takes the client address from X-Forwarded-For by default: an impostor that
    passes a hello on could write its victim's address there."""
    victim = Wire(url)
    relay, k = Wire(url), key(tokens["agent-a"])
    hello = {"key_id": identity.key_id(k), "nonce": NONCE}
    status, _, raw = relay.send(
        "POST", "/v1/hello", json.dumps(hello).encode(), {name: victim.client}
    )
    answer = json.loads(raw)
    assert status == 400 and answer["decision"] == "deny" and "mac" not in answer
    body = json.dumps(READ).encode()
    headers = {**bearer(tokens["agent-a"]), name: victim.client}
    status, got, raw = Wire(url).send("POST", "/v1/evaluate", body, headers)
    assert status == 400 and json.loads(raw)["decision"] == "deny" and "warden-mac" not in got


def test_main_turns_forwarded_addresses_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    warden.api.main(
        Settings(policy=BASIC_POLICY, audit_db=tmp_path / "a.db", admin_key="k" * 32, no_auth=True)
    )
    assert calls[0]["proxy_headers"] is False


def test_startup_warning_without_agents_names_the_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    warden.api.main(
        Settings(policy=BASIC_POLICY, audit_db=tmp_path / "a.db", admin_key="k" * 32, no_auth=True)
    )
    assert "can't tell Warden from another program on this port" in capsys.readouterr().err


def test_hello_is_refused_where_the_addresses_are_unknown(app: FastAPI) -> None:
    body = {"key_id": identity.key_id(key(ADMIN_KEY)), "nonce": NONCE}
    response = TestClient(app).post("/v1/hello", json=body)  # client address "testclient"
    assert response.status_code == 400 and response.json()["decision"] == "deny"


def test_one_agent_cant_use_up_anothers_hellos(
    app: FastAPI, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    w = app.state.warden
    w._hellos._clock = w._unknown_hellos._clock = lambda: now[0]
    with live_server(app) as url:
        wire = Wire(url)
        a, b = key(tokens["agent-a"]), key(tokens["agent-b"])
        for _ in range(warden.api.HELLOS_PER_MINUTE):
            assert w._hellos.acquire("agent-a") == 0
        fresh = identity.new_nonce  # real clients never reuse a nonce
        status, answer = wire.hello(a, fresh())
        assert status == 429 and answer["decision"] == "deny" and "mac" not in answer
        # Nor can a program without any token:
        for _ in range(warden.api.UNKNOWN_HELLOS_PER_MINUTE):
            assert w._unknown_hellos.acquire(":unknown") == 0
        assert wire.hello(b"nobody's", fresh())[0] == 429
        assert wire.hello(b, fresh())[0] == 200 and wire.hello(key(ADMIN_KEY), fresh())[0] == 200
        now[0] += 1  # refills
        assert wire.hello(a, fresh())[0] == 200 and wire.hello(b"nobody's", fresh())[0] == 401


@pytest.mark.parametrize(("limit", "hellos"), [(1, 6000), (5000, 20000), (90_000, 100_000)])
def test_hello_budget_is_above_the_request_budget(limit: int, hellos: int) -> None:
    from warden.limits import Limits, LimitSpec

    limits = Limits(agents={"x": LimitSpec(requests_per_minute=limit)})
    budget = warden.api._hello_limits(limits, ["x"])
    assert budget.requests_per_minute("x") == hellos
    assert budget.requests_per_minute(":admin") == 6000


# --- Signed answers -----------------------------------------------------------------------


def test_evaluate_answers_are_signed(url: str, tokens: dict[str, str]) -> None:
    body = json.dumps(READ).encode()
    for token in tokens.values():
        wire = Wire(url)
        answer = wire.send("POST", "/v1/evaluate", body, bearer(token))
        assert answer[0] == 200 and json.loads(answer[2])["decision"] == "allow"
        mac = wire.expected(key(token), "POST", "/v1/evaluate", body, answer)
        assert answer[1]["warden-mac"] == mac


def test_the_query_is_covered(url: str, tokens: dict[str, str]) -> None:
    wire, path = Wire(url), "/v1/approvals?agent_id=x&tool=%79"
    answer = wire.send("GET", path, None, ADMIN)
    assert answer[0] == 200
    mac = wire.expected(key(ADMIN_KEY), "GET", path, None, answer)
    assert answer[1]["warden-mac"] == mac


@pytest.mark.parametrize(
    ("body", "status"),
    [
        (b"{", 422),
        (b'{"tool": 1}', 422),
        (b'{"tool": "t", "tool": "t", "arguments": {}}', 422),
        (b"\xef\xbb\xbf{}", 422),
        (b'{"tool": "t", "arguments": {}, "agent_id": "someone-else"}', 403),
    ],
)
def test_refusals_are_signed(url: str, tokens: dict[str, str], body: bytes, status: int) -> None:
    wire, token = Wire(url), tokens["agent-a"]
    answer = wire.send("POST", "/v1/evaluate", body, bearer(token))
    assert answer[0] == status and json.loads(answer[2])["decision"] == "deny"
    mac = wire.expected(key(token), "POST", "/v1/evaluate", body, answer)
    assert answer[1]["warden-mac"] == mac


def test_crash_and_503_and_429_are_signed(
    app: FastAPI, url: str, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    w, token, body = app.state.warden, tokens["agent-a"], json.dumps(READ).encode()

    def ask(status: int) -> None:
        wire = Wire(url)
        answer = wire.send("POST", "/v1/evaluate", body, bearer(token))
        assert answer[0] == status and json.loads(answer[2])["decision"] == "deny"
        mac = wire.expected(key(token), "POST", "/v1/evaluate", body, answer)
        assert answer[1]["warden-mac"] == mac
        assert ("retry-after" in answer[1]) is (status == 429)

    def broken(*args: Any) -> None:
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(w.audit_log, "record", broken)
        ask(503)
    with monkeypatch.context() as m:
        m.setattr(warden.api, "apply_approval", broken)
        ask(500)
    with monkeypatch.context() as m:
        m.setattr(w.limiter, "acquire", lambda agent: 7.2)
        ask(429)


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        ("GET", "/v1/approvals?status=x", None, 422),
        ("POST", "/v1/approvals/nope/approve", b'{"action_hash": "%s"}' % (b"0" * 64), 404),
        ("POST", "/v1/approvals/nope/lift", None, 404),
        ("POST", "/v1/approvals/decide", b'{"ids": ["nope"], "approve": true}', 422),
        ("PUT", "/v1/approvals", b"{}", 405),
        ("GET", "/v1/approvals/nothing/here", None, 404),
    ],
)
def test_admin_answers_are_signed(
    url: str, method: str, path: str, body: bytes | None, status: int
) -> None:
    wire = Wire(url)
    answer = wire.send(method, path, body, ADMIN)
    assert answer[0] == status
    assert answer[1]["warden-mac"] == wire.expected(key(ADMIN_KEY), method, path, body, answer)


def test_a_body_that_was_not_read_is_not_signed(url: str, tokens: dict[str, str]) -> None:
    """Warden can't vouch for a question it hasn't seen: such answers carry no MAC."""
    headers = bearer(tokens["agent-a"])
    large = b" " * (64 * 1024 + 1)
    status, got, _ = Wire(url).send("POST", "/v1/evaluate", large, headers)
    assert status == 413 and "warden-mac" not in got
    wire = Wire(url)
    wire.conn.request("POST", "/v1/evaluate", iter([b"{}"]), headers, encode_chunked=True)
    response = wire.conn.getresponse()
    assert response.status == 411 and response.getheader("warden-mac") is None
    # A body where none belongs (the route never reads it):
    status, got, _ = Wire(url).send("GET", "/v1/approvals", b"{}", ADMIN)
    assert status == 200 and "warden-mac" not in got
    status, got, _ = Wire(url).send("GET", "/v1/approvals", None, {**ADMIN, "Content-Length": "0"})
    assert status == 200 and "warden-mac" in got


def test_only_with_the_right_secret_for_that_path(url: str, tokens: dict[str, str]) -> None:
    body, token = json.dumps(READ).encode(), tokens["agent-a"]

    def signed(method: str, path: str, headers: dict[str, str]) -> bool:
        data = body if method == "POST" else None
        return "warden-mac" in Wire(url).send(method, path, data, headers)[1]

    assert signed("POST", "/v1/evaluate", bearer(token))
    assert signed("GET", "/v1/approvals", ADMIN)
    assert not signed("POST", "/v1/evaluate", {"Warden-Nonce": NONCE})
    assert not signed("POST", "/v1/evaluate", bearer("wdn_" + "x" * 43))
    assert not signed("POST", "/v1/evaluate", ADMIN)
    assert not signed("GET", "/v1/approvals", bearer(token))
    assert not signed("GET", "/v1/approvals", {**ADMIN, "X-Warden-Admin-Key": "x"})
    assert not signed("GET", "/v1/approvalsx", ADMIN)
    assert not signed("GET", "/health", {**ADMIN, **bearer(token)})


@pytest.mark.parametrize("nonce", ["", "a" * 63, "A" * 64, "a" * 65, "x" * 64])
def test_a_malformed_nonce_gets_no_mac(url: str, tokens: dict[str, str], nonce: str) -> None:
    headers = bearer(tokens["agent-a"], nonce)
    status, got, _ = Wire(url).send("POST", "/v1/evaluate", json.dumps(READ).encode(), headers)
    assert status == 200 and "warden-mac" not in got


@pytest.mark.parametrize("twice", ["Warden-Nonce", "Authorization"])
def test_a_repeated_header_gets_no_mac(url: str, tokens: dict[str, str], twice: str) -> None:
    wire, body = Wire(url), json.dumps(READ).encode()
    wire.conn.putrequest("POST", "/v1/evaluate")
    for name, value in bearer(tokens["agent-a"]).items():
        wire.conn.putheader(name, value)
        if name == twice:
            wire.conn.putheader(name, value)
    wire.conn.putheader("content-type", "application/json")
    wire.conn.putheader("content-length", str(len(body)))
    wire.conn.endheaders(body)
    assert wire.conn.getresponse().getheader("warden-mac") is None


def test_plain_requests_are_unchanged(url: str, tokens: dict[str, str]) -> None:
    headers = {"Authorization": f"Bearer {tokens['agent-a']}"}
    status, got, raw = Wire(url).send("POST", "/v1/evaluate", json.dumps(READ).encode(), headers)
    assert status == 200 and json.loads(raw)["decision"] == "allow" and "warden-mac" not in got


def test_an_error_while_signing_is_a_500_without_a_mac(
    url: str, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError("no MAC today")

    monkeypatch.setattr("warden.api.identity.answer_mac", broken)
    body = json.dumps(READ).encode()
    status, got, raw = Wire(url).send("POST", "/v1/evaluate", body, bearer(tokens["agent-a"]))
    assert status == 500 and json.loads(raw)["decision"] == "deny" and "warden-mac" not in got


def run_signer(app: Any, guard: bool = False) -> list[Message]:
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "server": ("127.0.0.1", 1),
        "client": ("127.0.0.1", 2),
        "headers": [(b"Warden-Nonce", NONCE.encode())],
    }
    signer: Any = AnswerSigner(app, key_for=lambda scope: b"k" * 32)
    asyncio.run((CrashGuard(signer) if guard else signer)(scope, receive, send))
    return sent


def test_answers_in_pieces_are_signed_whole() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ab", "more_body": True})
        await send({"type": "http.response.body", "body": b"cd"})

    start, body = run_signer(app)
    assert body["body"] == b"abcd"
    mac = identity.answer_mac(
        b"k" * 32,
        nonce=NONCE,
        server="127.0.0.1:1",
        client="127.0.0.1:2",
        method="POST",
        target=b"/",
        request_sha256=hashlib.sha256(b"").hexdigest(),
        status=200,
        retry_after=b"",
        body=b"abcd",
    )
    assert start["headers"] == [(b"warden-mac", mac.encode())]


def test_an_unfinished_answer_is_never_sent_signed() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ab", "more_body": True})

    start, body = run_signer(app, guard=True)
    assert start["status"] == 500 and json.loads(body["body"])["decision"] == "deny"
    assert b"warden-mac" not in dict(start["headers"])


def test_no_answer_stays_no_answer() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:  # client went away
        return

    assert run_signer(app) == []


# --- Secrets stay secret --------------------------------------------------------------------


def test_keys_nonces_and_arguments_appear_nowhere(
    tmp_path: Path,
    app: FastAPI,
    tokens: dict[str, str],
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    token, k = tokens["agent-a"], key(tokens["agent-a"])
    secret = {"tool": "send_email", "arguments": {"to": "very-secret-argument"}}
    w = app.state.warden
    with live_server(app) as url:
        logging.getLogger("uvicorn.access").setLevel(logging.INFO)
        wire = Wire(url)
        wire.hello(k)
        wire.hello(b"unknown")
        wire.send("POST", "/v1/evaluate", json.dumps(secret).encode(), bearer(token))
        wire.send("POST", "/v1/evaluate", b"{", bearer(token))
        wire.send("GET", "/v1/approvals?ids=x", None, ADMIN)
    w.audit_log.recent()
    with sqlite3.connect(tmp_path / "audit.db") as db:
        dump = "\n".join(db.iterdump())
    stored = dump.encode() + b"".join(p.read_bytes() for p in tmp_path.glob("audit.db*"))
    captured = capsys.readouterr()
    text = caplog.text + captured.out + captured.err + repr(w) + repr(w.agents)
    assert '"POST /v1/hello HTTP/1.1" 200' in text  # the access log was on
    hidden = (token, k.hex(), key(ADMIN_KEY).hex(), ADMIN_KEY, NONCE, "very-secret-argument")
    for value in (*hidden, identity.key_id(k)):
        assert value not in text, "in a log or repr"
        assert value.encode() not in stored, "in the database"
    assert repr(k)[2:-1] not in text


# --- Hello budgets: only a caller that holds the key spends it ----------------------------


@pytest.fixture
def frozen_clock(app: FastAPI) -> list[float]:
    now = [0.0]
    w = app.state.warden
    w._hellos._clock = w._unknown_hellos._clock = lambda: now[0]
    w.clock = lambda: now[0]
    return now


def drain_unknown(app: FastAPI) -> None:
    for _ in range(warden.api.UNKNOWN_HELLOS_PER_MINUTE):
        assert app.state.warden._unknown_hellos.acquire(":unknown") == 0


@pytest.mark.parametrize("who", ["agent-a", "admin"])
def test_flooding_hellos_with_a_known_key_id_cant_lock_out_its_owner(
    app: FastAPI, tokens: dict[str, str], frozen_clock: list[float], who: str
) -> None:
    """The key id travels in the clear. A program that saw it sends hellos without
    client_mac: they come out of the shared unknown budget, never the owner's."""
    k = key(tokens[who] if who != "admin" else ADMIN_KEY)
    with live_server(app) as url:
        flood = Wire(url)
        for _ in range(warden.api.UNKNOWN_HELLOS_PER_MINUTE):
            assert flood.hello(k, identity.new_nonce(), proven=False)[0] == 200
        assert flood.hello(k, identity.new_nonce(), proven=False)[0] == 429
        # The owner (a real client, with client_mac) still gets through.
        assert Wire(url).hello(k, identity.new_nonce())[0] == 200
        client = WardenClient(url, token=tokens["agent-a"])
        assert client.evaluate("read_file", {"path": "/a"}).allowed


def test_a_wrong_or_replayed_client_mac_counts_as_unknown(
    app: FastAPI, tokens: dict[str, str], frozen_clock: list[float]
) -> None:
    k = key(tokens["agent-a"])
    with live_server(app) as url:
        wire = Wire(url)
        nonce = identity.new_nonce()
        assert wire.hello(k, nonce)[0] == 200  # first use: agent-a's budget
        drain_unknown(app)
        assert wire.hello(k, nonce)[0] == 429  # the same nonce again: unknown budget
        wrong = {
            "key_id": identity.key_id(k),
            "nonce": identity.new_nonce(),
            "client_mac": "0" * 64,
        }
        assert wire.send("POST", "/v1/hello", json.dumps(wrong).encode(), {})[0] == 429
        # A client_mac made for another connection (relayed) doesn't match this one.
        other = Wire(url)
        fresh = identity.new_nonce()
        relayed = {
            "key_id": identity.key_id(k),
            "nonce": fresh,
            "client_mac": identity.client_hello_mac(k, fresh, other.server, other.client),
        }
        assert wire.send("POST", "/v1/hello", json.dumps(relayed).encode(), {})[0] == 429
        assert wire.hello(k, identity.new_nonce())[0] == 200  # a real one still works


def test_without_client_mac_a_hello_is_still_answered(url: str, tokens: dict[str, str]) -> None:
    """Plain HTTP clients may leave client_mac out: same answer, shared budget."""
    wire, k = Wire(url), key(tokens["agent-b"])
    status, answer = wire.hello(k, proven=False)
    assert status == 200
    assert answer["mac"] == identity.hello_mac(k, NONCE, wire.server, wire.client)


@pytest.mark.parametrize("bad", ["", "x" * 64, "A" * 64, "0" * 63])
def test_malformed_client_mac_is_refused(url: str, tokens: dict[str, str], bad: str) -> None:
    body = {"key_id": identity.key_id(key(tokens["agent-a"])), "nonce": NONCE, "client_mac": bad}
    assert Wire(url).send("POST", "/v1/hello", json.dumps(body).encode(), {})[0] == 422


def test_seen_nonces_expire_and_are_capped(
    app: FastAPI, frozen_clock: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    w = app.state.warden
    assert w._first_use("a" * 64) and not w._first_use("a" * 64)
    frozen_clock[0] += 60
    assert w._first_use("a" * 64)  # a minute later it is forgotten
    monkeypatch.setattr(warden.api, "MAX_SEEN_HELLO_NONCES", 1)
    assert not w._first_use("b" * 64)  # full: counts as unknown (fail safe)
    frozen_clock[0] += 61
    assert w._first_use("b" * 64)
    assert "a" * 64 not in repr(w)


def test_only_expired_nonces_are_forgotten(app: FastAPI, frozen_clock: list[float]) -> None:
    w = app.state.warden
    assert w._first_use("a" * 64)
    frozen_clock[0] += 30
    assert w._first_use("b" * 64)
    frozen_clock[0] += 31  # "a" is past a minute, "b" isn't
    assert not w._first_use("b" * 64)
    assert w._first_use("a" * 64)
