"""The client's side of the proof: with a token, nothing secret is sent before Warden has
proven itself, and only a correctly signed answer counts. Impostors are raw sockets."""

import asyncio
import contextlib
import http.client
import json
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from helpers import ADMIN_KEY, BASIC_POLICY, live_server, shown
from proof import Proving, http_answer, raw_impostor, read_message, serving, valid_hello

import warden.api
from warden import identity
from warden.agents import add_agent, load_agents
from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore
from warden.audit import SQLiteAuditLog
from warden.client import (
    MAX_HELLO_BYTES,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    NOT_PROVEN,
    Answer,
    NotProven,
    WardenClient,
    _DeadlineSocket,
    ask_proven,
)
from warden.models import Decision
from warden.sdk import ApprovalPending, NotAllowed, default_client, run_guarded, run_guarded_async

TOKEN = "wdn_" + "T" * 43
KEY = identity.proof_key(TOKEN)
PRIVATE = "argument-nobody-may-see"
ALLOW = b'{"decision": "allow", "reason": "evil"}'


def denied_unproven(answer: Answer) -> bool:
    return (
        answer.decision is Decision.DENY
        and answer.reason.startswith(NOT_PROVEN)
        and not answer.unreachable
        and answer.retry_after is None
        and answer.approval_id is None
    )


def ask(url: str, token: str = TOKEN, timeout: float = 2) -> Answer:
    return WardenClient(url, token=token, timeout=timeout).evaluate("t", {"x": PRIVATE})


# --- Impostors (raw sockets): deny, the tool doesn't run, and they learn nothing ----------


def always_allow(sock: socket.socket) -> None:
    read_message(sock)
    sock.sendall(http_answer(ALLOW))


def run_sync(url: str, ran: list[str]) -> None:
    client = WardenClient(url, token=TOKEN, timeout=2)
    run_guarded("t", {"x": PRIVATE}, lambda x: ran.append(x), client=client, wait_for_approval=2)


def run_async(url: str, ran: list[str]) -> None:
    async def tool(x: str) -> None:
        ran.append(x)

    client = WardenClient(url, token=TOKEN, timeout=2)
    asyncio.run(run_guarded_async("t", {"x": PRIVATE}, tool, client=client, wait_for_approval=2))


def nothing_secret(received: bytes | bytearray) -> bool:
    return (
        TOKEN.encode() not in received
        and PRIVATE.encode() not in received
        and b"uthorization" not in received
        and KEY.hex().encode() not in received
    )


@pytest.mark.parametrize("run", [run_sync, run_async])
def test_impostor_that_always_allows(run: Callable[[str, list[str]], None]) -> None:
    ran: list[str] = []
    with raw_impostor(always_allow) as (port, received):
        with pytest.raises(NotAllowed, match=NOT_PROVEN):
            run(f"http://127.0.0.1:{port}", ran)
    assert ran == []
    assert received.count(b"POST ") == 1 and b"POST /v1/hello " in received
    assert nothing_secret(received)


BAD_HELLOS: dict[str, Callable[[socket.socket], bytes]] = {
    "404": lambda s: http_answer(b'{"decision": "deny"}', "404 Not Found"),
    "401": lambda s: http_answer(b"{}", "401 Unauthorized"),
    "429": lambda s: http_answer(b"{}", "429 Too Many", "Retry-After: 1"),
    "500": lambda s: http_answer(valid_hello(s, TOKEN), "500 Oops"),
    "201": lambda s: http_answer(valid_hello(s, TOKEN), "201 Created"),
    "302": lambda s: http_answer(b"", "302 Found", "Location: /v1/hello"),
    "not http": lambda s: b"garbage\r\n\r\n",
    "no json": lambda s: http_answer(b"<html>"),
    "list": lambda s: http_answer(b"[]"),
    "empty": lambda s: http_answer(b"{}"),
    "null": lambda s: http_answer(b'{"mac": null}'),
    "number": lambda s: http_answer(b'{"mac": 5}'),
    "wrong": lambda s: http_answer(b'{"mac": "%s"}' % (b"0" * 64)),
    "uppercase": lambda s: http_answer(valid_hello(s, TOKEN).upper().replace(b"MAC", b"mac")),
    "truncated": lambda s: http_answer(valid_hello(s, TOKEN)[:-3] + b'"}'),
    "oversized": lambda s: http_answer(valid_hello(s, TOKEN) + b" " * MAX_HELLO_BYTES),
    "bad length": lambda s: b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n{",
    "deep": lambda s: http_answer(b"[" * 4000),
    "header flood": lambda s: b"HTTP/1.1 200 OK\r\n" + b"x: y\r\n" * 200 + b"\r\n",
}


@pytest.mark.parametrize("which", BAD_HELLOS)
def test_bad_hello_answers(which: str) -> None:
    def act(sock: socket.socket) -> None:
        sock.sendall(BAD_HELLOS[which](sock))
        if which == "bad length":
            sock.shutdown(socket.SHUT_WR)

    with raw_impostor(act) as (port, received):
        answer = ask(f"http://127.0.0.1:{port}")
    assert denied_unproven(answer)
    assert received.count(b"POST ") == 1 and nothing_secret(received)
    assert ("wrong or removed secret" in answer.reason) is (which == "401")


def test_the_raw_impostor_could_have_passed() -> None:
    """The cases above differ from this one only in their one mistake."""

    def act(sock: socket.socket) -> None:
        sock.sendall(http_answer(valid_hello(sock, TOKEN)))

    with raw_impostor(act) as (port, received):
        ask(f"http://127.0.0.1:{port}", timeout=0.5)
    assert TOKEN.encode() in received


@pytest.mark.parametrize("how", ["silent", "drip", "endless 100 Continue"])
def test_slow_hello_ends_at_the_timeout(how: str) -> None:
    """The timeout is for everything together: single bytes don't extend it."""

    def act(sock: socket.socket) -> None:
        read_message(sock)
        while how != "silent":
            sock.sendall(b"H" if how == "drip" else b"HTTP/1.1 100 Continue\r\n\r\n")
            time.sleep(0.05)

    with raw_impostor(act) as (port, received):
        started = time.monotonic()
        answer = ask(f"http://127.0.0.1:{port}", timeout=0.5)
        assert 0.4 < time.monotonic() - started < 2
    assert denied_unproven(answer) and "in time" in answer.reason
    assert nothing_secret(received)


def test_hello_and_answer_share_the_timeout() -> None:
    def act(sock: socket.socket) -> None:
        hello = http_answer(valid_hello(sock, TOKEN))
        time.sleep(0.6)
        sock.sendall(hello)
        read_message(sock)
        time.sleep(0.6)
        sock.sendall(http_answer(ALLOW))

    with raw_impostor(act) as (port, _):
        answer = ask(f"http://127.0.0.1:{port}", timeout=1)
    assert not answer.allowed and answer.unreachable  # it was Warden: a wait may go on


def test_after_the_deadline_nothing_is_read_or_sent() -> None:
    ours, theirs = socket.socketpair()
    with theirs, _DeadlineSocket(fileno=ours.detach()) as sock:
        sock.deadline = time.monotonic()
        theirs.sendall(b"late")
        with pytest.raises(TimeoutError):
            sock.recv_into(bytearray(4))
        with pytest.raises(TimeoutError):
            sock.sendall(b"late")


def test_connect_timeout_is_not_proven(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(self: Any) -> None:
        raise TimeoutError

    monkeypatch.setattr(http.client.HTTPConnection, "connect", slow)
    assert denied_unproven(ask("http://127.0.0.1:1"))


def test_no_token_and_odd_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Can't name this connection's ends (e.g. a patched socket): deny, nothing sent."""

    def broken(addr: object) -> str:
        raise ValueError("not a TCP address")

    with raw_impostor(always_allow) as (port, received):
        monkeypatch.setattr("warden.client.identity.address", broken)
        answer = ask(f"http://127.0.0.1:{port}")
    assert answer.decision is Decision.DENY and not answer.unreachable
    assert received == b""


# --- The good path, against a real Warden ----------------------------------------------------


@pytest.fixture
def tokens(tmp_path: Path) -> dict[str, str]:
    return {name: add_agent(tmp_path / "agents.json", name) for name in ("agent-a", "agent-b")}


def make_app(tmp_path: Path, policy: Path = BASIC_POLICY) -> FastAPI:
    return create_app(
        policy,
        audit_log=SQLiteAuditLog(tmp_path / "audit.db"),
        approvals=ApprovalStore(db=ApprovalDB(tmp_path / "audit.db")),
        admin_key=ADMIN_KEY,
        agents=load_agents(tmp_path / "agents.json"),
    )


@pytest.fixture
def app(tmp_path: Path, tokens: dict[str, str]) -> FastAPI:
    return make_app(tmp_path)


@pytest.fixture
def url(app: FastAPI) -> Iterator[str]:
    with live_server(app) as base:
        yield base


def test_decisions(url: str, tokens: dict[str, str]) -> None:
    for token in tokens.values():
        client = WardenClient(url, token=token)
        assert client.evaluate("read_file", {"path": "/ä"}).allowed
        assert client.evaluate("read_file", {"blob": "x" * 60_000}).allowed
        denied = client.evaluate("delete_file", {"path": "/a"})
        assert denied.decision is Decision.DENY and NOT_PROVEN not in denied.reason
        pending = client.evaluate("send_email", {"to": "x@y.z"})
        assert pending.decision is Decision.REQUIRE_APPROVAL and pending.approval_id is not None
        assert client.evaluate("Bad Tool", {}) == Answer(Decision.DENY, "invalid request")


def test_localhost_works(url: str, tokens: dict[str, str]) -> None:
    by_name = url.replace("127.0.0.1", "localhost")
    assert WardenClient(by_name, token=tokens["agent-a"]).evaluate("read_file", {}).allowed


@pytest.mark.parametrize("host", ["::1", "0.0.0.0"])  # noqa: S104 (what a user might run)
def test_other_ways_to_listen(tmp_path: Path, tokens: dict[str, str], host: str) -> None:
    """IPv6, and a wildcard address: both ends are named by the connection itself."""
    try:
        socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET).bind((host, 0))
    except OSError:
        pytest.skip("no IPv6 here")
    config = uvicorn.Config(make_app(tmp_path), host=host, port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://[::1]:{port}" if ":" in host else f"http://127.0.0.1:{port}"
    try:
        assert WardenClient(url, token=tokens["agent-a"]).evaluate("read_file", {}).allowed
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_signed_refusals_keep_their_meaning(
    app: FastAPI, url: str, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, w = WardenClient(url, token=tokens["agent-a"]), app.state.warden

    def broken(*args: Any) -> None:
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(w.limiter, "acquire", lambda agent: 7.2)
        limited = client.evaluate("read_file", {})
    assert limited == Answer(Decision.DENY, "rate limit exceeded", retry_after=8.0)
    with monkeypatch.context() as m:
        m.setattr(w.audit_log, "record", broken)
        assert client.evaluate("read_file", {}).reason == "audit log unavailable"
    with monkeypatch.context() as m:
        m.setattr(warden.api, "apply_approval", broken)
        assert client.evaluate("read_file", {}).reason == "internal error"
    mixed_up = WardenClient(url, "agent-b", token=tokens["agent-a"]).evaluate("read_file", {})
    assert mixed_up.reason == "agent_id does not match the agent token"


def test_an_error_while_signing_is_a_deny(
    url: str, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = identity.answer_mac

    def broken(*args: Any, **kwargs: Any) -> str:
        if threading.current_thread() is not threading.main_thread():  # the server
            raise RuntimeError
        return real(*args, **kwargs)

    monkeypatch.setattr(identity, "answer_mac", broken)
    assert denied_unproven(WardenClient(url, token=tokens["agent-a"]).evaluate("read_file", {}))


def test_unknown_and_unusable_tokens_are_denied(url: str) -> None:
    for token in (TOKEN, "", "x", "wdn_\udcff", "wdn_\nX: y", "wdn_€"):
        assert denied_unproven(ask(url, token))


def test_token_against_a_warden_without_agents(tmp_path: Path) -> None:
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    with live_server(app) as url:
        assert denied_unproven(WardenClient(url, token=TOKEN).evaluate("read_file", {}))
        # Without a token, nothing changed:
        assert WardenClient(url, "a").evaluate("read_file", {"path": "/a"}).allowed


def test_without_a_token_nothing_is_proven(tmp_path: Path) -> None:
    """Documented: there is no shared secret, so the port is trusted."""
    with raw_impostor(always_allow) as (port, received):
        assert WardenClient(f"http://127.0.0.1:{port}", "a", timeout=2).evaluate("t", {}).allowed
    assert b"/v1/hello" not in received


@pytest.mark.parametrize("name", ["WARDEN_PROOF", "WARDEN_INSECURE", "WARDEN_NO_PROOF"])
def test_the_environment_client_demands_proof(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_AGENT_TOKEN", TOKEN)
    monkeypatch.setenv(name, "0")
    with raw_impostor(always_allow) as (port, received):
        monkeypatch.setenv("WARDEN_URL", f"http://127.0.0.1:{port}")
        assert denied_unproven(default_client().evaluate("t", {"x": PRIVATE}))
    assert nothing_secret(received)


def test_proxy_settings_are_ignored(
    url: str, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert WardenClient(url, token=tokens["agent-a"]).evaluate("read_file", {}).allowed


# --- Wrong MACs on the answer: each is a deny ---------------------------------------------------


class Fake(Proving):
    """Proves itself with the token's key; `do` then sends the answer."""

    secrets = (TOKEN,)
    do: Callable[["Fake"], None]

    def answer(self) -> None:
        type(self).do(self)


def fake_answer(do: Callable[[Fake], None], token: str = TOKEN) -> Answer:
    handler = type("Handler", (Fake,), {"do": do, "secrets": (TOKEN, token)})
    with serving(handler) as url:
        return ask(url, token)


OK = b'{"decision": "allow", "reason": "ok"}'


def mac_sent(change: Callable[[Fake, str], dict[str, str] | list[str]]) -> Callable[[Fake], None]:
    def do(fake: Fake) -> None:
        headers = change(fake, fake.mac(200, OK, {}))
        if isinstance(headers, list):
            fake.send_response(200)
            for value in headers:
                fake.send_header("Warden-Mac", value)
            fake.send_header("content-length", str(len(OK)))
            fake.end_headers()
            fake.wfile.write(OK)
        else:
            fake.raw_reply(200, OK, headers)

    return do


def flip(mac: str) -> str:
    return f"{int(mac, 16) ^ 1:064x}"


def test_a_correct_mac_is_accepted() -> None:
    assert fake_answer(lambda fake: fake.reply(200, OK)).allowed
    assert fake_answer(mac_sent(lambda fake, mac: [mac])).allowed


@pytest.mark.parametrize(
    "change",
    [
        lambda fake, mac: {},
        lambda fake, mac: {"Warden-Mac": ""},
        lambda fake, mac: [mac, mac],
        lambda fake, mac: [mac, flip(mac)],
        lambda fake, mac: {"Warden-Mac": f"{mac}, {mac}"},
        lambda fake, mac: {"Warden-Mac": mac.upper()},
        lambda fake, mac: {"Warden-Mac": mac[:-1]},
        lambda fake, mac: {"Warden-Mac": mac[:32]},
        lambda fake, mac: {"Warden-Mac": mac + "0"},
        lambda fake, mac: {"Warden-Mac": flip(mac)},
        lambda fake, mac: {"X-Warden-Mac": mac},
        # Another agent's key:
        lambda fake, mac: {
            "Warden-Mac": fake.mac(200, OK, {}, key=identity.proof_key("wdn_other"))
        },
        # A hello MAC in place of an answer MAC:
        lambda fake, mac: {
            "Warden-Mac": identity.hello_mac(KEY, fake.headers["Warden-Nonce"], *fake.ends())
        },
        # The MAC of another answer:
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, nonce="0" * 64)},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, request_sha256="0" * 64)},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, target=b"/v1/approvals")},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, target=b"/v1/evaluate?a=b")},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, method="GET")},
        lambda fake, mac: {"Warden-Mac": fake.mac(429, OK, {})},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK + b" ", {})},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, server="127.0.0.1:1")},
        lambda fake, mac: {"Warden-Mac": fake.mac(200, OK, {}, client="127.0.0.1:1")},
        lambda fake, mac: {"Warden-Mac": mac, "Retry-After": "1"},  # added on the way
    ],
)
def test_wrong_macs(change: Callable[[Fake, str], dict[str, str] | list[str]]) -> None:
    assert denied_unproven(fake_answer(mac_sent(change)))


@pytest.mark.parametrize("sent", ["9", "", None, "8, 7"])
def test_retry_after_is_covered(sent: str | None) -> None:
    def do(fake: Fake) -> None:
        mac = fake.mac(429, b"{}", {"Retry-After": "7"})
        extra = {} if sent is None else {"Retry-After": sent}
        fake.raw_reply(429, b"{}", {"Warden-Mac": mac, **extra})

    assert denied_unproven(fake_answer(do))
    signed = fake_answer(
        lambda fake: fake.reply(429, b'{"decision": "deny"}', {"Retry-After": "7"})
    )
    assert signed == Answer(Decision.DENY, "rate limit exceeded", retry_after=7.0)


def test_an_unsigned_error_is_a_plain_deny() -> None:
    """Its reason and Retry-After don't count either."""

    def do(fake: Fake) -> None:
        fake.raw_reply(429, b'{"decision": "deny", "reason": "x"}', {"Retry-After": "1"})

    assert denied_unproven(fake_answer(do))


def test_a_signed_error_status_is_never_an_allow() -> None:
    answer = fake_answer(lambda fake: fake.reply(500, OK))
    assert answer == Answer(Decision.DENY, "Warden returned HTTP 500")


def test_oversized_and_cut_off_answers_are_denied() -> None:
    large = fake_answer(lambda fake: fake.reply(200, OK + b" " * 70_000))
    assert large == Answer(Decision.DENY, "answer from Warden too large")

    def cut_off(fake: Fake) -> None:
        fake.send_response(200)
        fake.send_header("Warden-Mac", fake.mac(200, OK, {}))
        fake.send_header("content-length", str(len(OK) + 1))
        fake.end_headers()
        fake.wfile.write(OK)
        fake.close_connection = True

    answer = fake_answer(cut_off)  # Warden died while answering: a wait may go on
    assert not answer.allowed and answer.unreachable


def test_exact_limits() -> None:
    reply = OK + b" " * (MAX_RESPONSE_BYTES - len(OK))
    assert fake_answer(lambda fake: fake.reply(200, reply)).allowed
    over = fake_answer(lambda fake: fake.reply(200, reply + b" "))
    assert over.reason == "answer from Warden too large"

    for extra in (0, 1):

        def act(sock: socket.socket, extra: int = extra) -> None:
            hello = valid_hello(sock, TOKEN)
            sock.sendall(http_answer(hello + b" " * (MAX_HELLO_BYTES - len(hello) + extra)))
            read_message(sock)
            sock.close()

        with raw_impostor(act) as (port, received):
            answer = ask(f"http://127.0.0.1:{port}")
        assert answer.unreachable is (extra == 0)  # i.e. accepted, then lost
        assert (TOKEN.encode() in received) is (extra == 0)


def test_the_largest_request_is_still_sent() -> None:
    spare = MAX_REQUEST_BYTES - len(b'{"tool": "t", "arguments": {"x": ""}}')
    handler = type("Handler", (Fake,), {"do": lambda fake: fake.reply(200, OK)})
    with serving(handler) as url:
        client = WardenClient(url, token=TOKEN, timeout=5)
        assert client.evaluate("t", {"x": "x" * spare}).allowed
        assert "too large" in client.evaluate("t", {"x": "x" * (spare + 1)}).reason


def test_a_signed_redirect_is_not_an_allow() -> None:
    assert fake_answer(lambda fake: fake.reply(300, OK)).reason == "Warden returned HTTP 300"


@pytest.mark.parametrize("status", ["401 Unauthorized", "404 Not Found"])
def test_only_a_401_says_the_key_is_unknown(status: str) -> None:
    with raw_impostor(lambda s: s.sendall(http_answer(b"{}", status))) as (port, _):
        args: Any = (f"http://127.0.0.1:{port}", KEY, "GET", "/", None, {})
        with pytest.raises(NotProven) as caught:
            ask_proven(*args, timeout=2, limit=10)
    assert caught.value.unknown_key is status.startswith("401")


def test_an_old_answer_cant_be_replayed() -> None:
    """Everything the impostor recorded from a real exchange, on a later question."""
    recorded: list[tuple[str, bytes]] = []

    def do(fake: Fake) -> None:
        recorded.append((fake.mac(200, OK, {}), OK))
        mac, body = recorded[0]
        fake.raw_reply(200, body, {"Warden-Mac": mac})

    handler = type("Handler", (Fake,), {"do": do})
    with serving(handler) as url:
        assert ask(url).allowed
        assert denied_unproven(ask(url))
    assert recorded[0] != recorded[1]


def test_token_of_one_agent_with_the_key_of_another(url: str, tokens: dict[str, str]) -> None:
    """Warden signs with the key of the agent whose token arrived, not of the hello's."""
    body = json.dumps({"tool": "read_file", "arguments": {}}).encode()

    def mixed(hello: str, sent: str) -> int:
        headers = {"content-type": "application/json", "authorization": f"Bearer {tokens[sent]}"}
        key = identity.proof_key(tokens[hello])
        args: Any = (url, key, "POST", "/v1/evaluate", body, headers)
        return ask_proven(*args, timeout=5, limit=10_000).status

    assert mixed("agent-a", "agent-a") == 200
    with pytest.raises(NotProven):
        mixed("agent-b", "agent-a")


# --- Relays ------------------------------------------------------------------------------------


def relay_to(target: tuple[str, int], extra: bytes = b"") -> Callable[[socket.socket], None]:
    def act(sock: socket.socket) -> None:
        with socket.create_connection(target) as upstream:
            while request := read_message(sock):
                if extra:
                    head, _, rest = request.partition(b"\r\n")
                    peer = identity.address(sock.getpeername()).encode()
                    request = head + b"\r\n" + extra % peer + b"\r\n" + rest
                upstream.sendall(request)
                sock.sendall(read_message(upstream))

    return act


@pytest.mark.parametrize("extra", [b"", b"X-Forwarded-For: %s"])
def test_relay_to_a_real_warden_on_another_port(
    url: str, tokens: dict[str, str], extra: bytes
) -> None:
    port = int(url.rsplit(":", 1)[1])
    with raw_impostor(relay_to(("127.0.0.1", port), extra)) as (impostor, received):
        answer = ask(f"http://127.0.0.1:{impostor}", tokens["agent-a"])
    assert denied_unproven(answer) and "in time" not in answer.reason
    assert b"/v1/hello" in received and tokens["agent-a"].encode() not in received
    assert PRIVATE.encode() not in received


def test_localhost_where_the_impostor_has_ipv6(
    url: str, tokens: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`localhost` is tried as ::1 first; the impostor there passes hellos on to Warden."""
    port = int(url.rsplit(":", 1)[1])
    real = socket.getaddrinfo

    def both(host: str, *args: Any, **kwargs: Any) -> Any:
        if host != "localhost":
            return real(host, *args, **kwargs)
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", both)
    client = WardenClient(f"http://localhost:{port}", token=tokens["agent-a"], timeout=2)
    assert client.evaluate("read_file", {}).allowed  # nothing on ::1: the next address
    try:
        with raw_impostor(relay_to(("127.0.0.1", port)), "::1", port) as (_, received):
            assert denied_unproven(client.evaluate("t", {"x": PRIVATE}))
    except OSError:
        pytest.skip("no IPv6 here")
    assert b"/v1/hello" in received and tokens["agent-a"].encode() not in received


def test_impostor_that_accepted_before_warden_started(
    tmp_path: Path, tokens: dict[str, str]
) -> None:
    """The hole the server address alone leaves: the impostor takes a connection while
    Warden is down, frees the port, Warden starts on the SAME port, and the impostor
    passes the hello on to it. Warden signs the impostor's own client address."""
    accepted: list[socket.socket] = []
    answers: list[Answer] = []
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    client = WardenClient(f"http://127.0.0.1:{port}", token=tokens["agent-a"], timeout=8)
    agent = threading.Thread(target=lambda: answers.append(client.evaluate("t", {"x": PRIVATE})))
    agent.start()
    accepted.append(listener.accept()[0])
    listener.close()
    config = uvicorn.Config(make_app(tmp_path), host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    seen = b""
    with accepted[0] as sock, socket.create_connection(("127.0.0.1", port)) as upstream:
        sock.settimeout(5)
        assert upstream.getpeername() == sock.getsockname()  # the same server address
        seen += read_message(sock)
        upstream.sendall(seen)
        relayed = read_message(upstream)
        assert b" 200 OK" in relayed and b'"mac"' in relayed  # Warden did answer
        sock.sendall(relayed)
        with contextlib.suppress(OSError):
            seen += sock.recv(65536)
    agent.join(timeout=10)
    server.should_exit = True
    thread.join(timeout=5)
    assert denied_unproven(answers[0]) and "in time" not in answers[0].reason
    assert tokens["agent-a"].encode() not in seen and PRIVATE.encode() not in seen


def test_port_taken_between_hello_and_question() -> None:
    """The connection closes after a good hello; the client must not reconnect."""
    handed_over = threading.Event()
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        def warden_then_impostor() -> None:
            sock, _ = listener.accept()
            with sock:
                sock.sendall(http_answer(valid_hello(sock, TOKEN), "200 OK", "Connection: close"))
            handed_over.set()

        thread = threading.Thread(target=warden_then_impostor)
        thread.start()
        answer = ask(f"http://127.0.0.1:{port}")
        assert handed_over.wait(5)
        thread.join(timeout=5)
        listener.settimeout(0.3)
        with pytest.raises(TimeoutError):  # nobody connects again
            listener.accept()
    assert not answer.allowed and answer.unreachable


@pytest.mark.parametrize("reset", [False, True])
def test_connection_lost_after_the_hello(reset: bool) -> None:
    def act(sock: socket.socket) -> None:
        sock.sendall(http_answer(valid_hello(sock, TOKEN)))
        read_message(sock)
        if reset:
            linger = b"\x01\x00\x00\x00\x00\x00\x00\x00"
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        sock.close()

    with raw_impostor(act) as (port, _):
        answer = ask(f"http://127.0.0.1:{port}")
    assert not answer.allowed and answer.unreachable


def test_connection_lost_before_the_hello_answer_is_unreachable() -> None:
    def act(sock: socket.socket) -> None:
        read_message(sock)
        sock.close()

    with raw_impostor(act) as (port, received):
        answer = ask(f"http://127.0.0.1:{port}")
    assert not answer.allowed and answer.unreachable
    assert nothing_secret(received)


# --- Waiting for a human ------------------------------------------------------------------------


PENDING = (
    b'{"decision": "require_approval", "reason": "ask", "approval_id": "appr-0123456789abcdef"}'
)


@pytest.mark.parametrize("is_async", [False, True])
def test_a_failed_proof_ends_the_wait(is_async: bool) -> None:
    questions: list[int] = []

    def do(fake: Fake) -> None:
        questions.append(1)
        if len(questions) < 3:
            fake.reply(200, PENDING)
        else:
            fake.raw_reply(200, OK, {})  # an unsigned allow, and everything after it

    ran: list[str] = []

    async def tool() -> None:
        ran.append("x")

    handler = type("Handler", (Fake,), {"do": do})
    with serving(handler) as url:
        client = WardenClient(url, token=TOKEN, timeout=2)
        options: Any = {"client": client, "wait_for_approval": 20, "poll_seconds": 0.02}
        started = time.monotonic()
        with pytest.raises(NotAllowed, match=NOT_PROVEN):
            if is_async:
                asyncio.run(run_guarded_async("t", {}, tool, **options))
            else:
                run_guarded("t", {}, lambda: ran.append("x"), **options)
        assert time.monotonic() - started < 10
    assert ran == [] and len(questions) == 3


def test_refused_connections_dont_end_the_wait(tmp_path: Path, tokens: dict[str, str]) -> None:
    """Warden restarts during a wait (really down for several polls), then a human approves."""

    def start(port: int) -> tuple[FastAPI, uvicorn.Server, threading.Thread]:
        app = make_app(tmp_path)
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        while not server.started:
            time.sleep(0.01)
        return app, server, thread

    app, server, thread = start(0)
    port = server.servers[0].sockets[0].getsockname()[1]
    client = WardenClient(f"http://127.0.0.1:{port}", token=tokens["agent-a"])
    assert client.evaluate("send_email", {"to": "x"}).decision is Decision.REQUIRE_APPROVAL
    ran: list[str] = []
    problems: list[Exception] = []

    def agent() -> None:
        try:
            run_guarded(
                "send_email",
                {"to": "x"},
                lambda to: ran.append(to),
                client=client,
                wait_for_approval=15,
                poll_seconds=0.05,
            )
        except Exception as exc:
            problems.append(exc)

    worker = threading.Thread(target=agent)
    worker.start()
    time.sleep(0.3)
    server.should_exit = True
    thread.join(timeout=10)
    time.sleep(0.3)
    app, server, thread = start(port)
    store, admin = app.state.warden.approvals, {"X-Warden-Admin-Key": ADMIN_KEY}
    while not problems and not (store.pending() and store.pending()[0][0].arguments):
        time.sleep(0.01)
    if not problems:
        human = TestClient(app)
        approval_id = store.pending()[0][0].approval_id
        body = shown(human, approval_id, admin)
        human.post(f"/v1/approvals/{approval_id}/approve", headers=admin, json=body)
    worker.join(timeout=10)
    server.should_exit = True
    thread.join(timeout=10)
    assert problems == [] and ran == ["x"]


def test_an_impostor_during_a_restart_ends_the_wait(tmp_path: Path, tokens: dict[str, str]) -> None:
    """Warden stops while the agent waits; someone else takes the port."""
    ran: list[str] = []
    problems: list[Exception] = []
    with live_server(make_app(tmp_path)) as url:
        client = WardenClient(url, token=tokens["agent-a"], timeout=2)

        def agent() -> None:
            try:
                run_guarded(
                    "send_email",
                    {"to": PRIVATE},
                    lambda to: ran.append(to),
                    client=client,
                    wait_for_approval=20,
                    poll_seconds=0.05,
                )
            except NotAllowed as exc:
                problems.append(exc)

        worker = threading.Thread(target=agent)
        worker.start()
        time.sleep(0.3)
    port = int(url.rsplit(":", 1)[1])
    with raw_impostor(always_allow, port=port) as (_, received):
        worker.join(timeout=10)
    assert ran == [] and NOT_PROVEN in str(problems[0])
    assert tokens["agent-a"].encode() not in received
    assert PRIVATE.encode() not in received


def test_pending_without_waiting(url: str, tokens: dict[str, str]) -> None:
    with pytest.raises(ApprovalPending):
        run_guarded(
            "send_email", {"to": "x"}, print, client=WardenClient(url, token=tokens["agent-a"])
        )


# --- The client keeps its secrets to itself -----------------------------------------------------


def test_the_client_shows_no_secrets(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    client = WardenClient(token=TOKEN)
    texts = [repr(client)]
    with raw_impostor(always_allow) as (port, _):
        answer = ask(f"http://127.0.0.1:{port}")
        with pytest.raises(NotAllowed) as caught:
            run_sync(f"http://127.0.0.1:{port}", [])
    texts += [repr(answer), repr(caught.value), str(caught.value.__cause__), caplog.text]
    texts += [str(caught.value.__context__), *capsys.readouterr()]
    for value in (TOKEN, KEY.hex(), repr(KEY), PRIVATE):
        assert all(value not in text for text in texts)
