"""warden.client: asks Warden, and fails closed on anything unexpected."""

import http.server
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from helpers import ADMIN_KEY, BASIC_POLICY, live_server

from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import (
    Answer,
    ClientConfigError,
    WardenClient,
    check_url,
    parse_answer,
)
from warden.models import Decision


@pytest.fixture
def url(tmp_path: Path) -> Iterator[str]:
    app = create_app(
        BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "audit.db"), admin_key=ADMIN_KEY
    )
    with live_server(app) as base:
        yield base


def test_allow_deny_and_approval(url: str) -> None:
    client = WardenClient(url, "agent-1")
    assert client.evaluate("read_file", {"path": "/a"}).allowed
    denied = client.evaluate("delete_file", {"path": "/a"})
    assert denied.decision is Decision.DENY and not denied.allowed
    pending = client.evaluate("send_email", {"to": "x@y.z"})
    assert pending.decision is Decision.REQUIRE_APPROVAL
    assert pending.approval_id is not None and pending.action_hash is not None


def test_http_error_is_deny_with_warden_reason(url: str) -> None:
    answer = WardenClient(url, "agent-1").evaluate("Bad Tool", {})
    assert answer.decision is Decision.DENY
    assert answer.reason == "invalid request"


def test_unreachable_is_deny() -> None:
    answer = WardenClient("http://127.0.0.1:9", "a", timeout=0.5).evaluate("read_file", {})
    assert answer == Answer(Decision.DENY, "Warden unreachable")


def test_unserializable_arguments_are_deny(url: str) -> None:
    answer = WardenClient(url, "a").evaluate("read_file", {"x": float("nan")})
    assert answer.decision is Decision.DENY


@pytest.mark.parametrize(
    "bad",
    [
        "https://127.0.0.1:8000",
        "http://example.com:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:8000/v1",
        "http://user@127.0.0.1:8000",
        "http://127.0.0.1:8000?x=1",
        "http://127.0.0.1:99999",
        "http://127.0.0.1.evil.net:80",
        "file:///etc/passwd",
    ],
)
def test_only_local_urls(bad: str) -> None:
    with pytest.raises(ClientConfigError):
        check_url(bad)


def test_local_urls_accepted() -> None:
    assert check_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    assert check_url("http://localhost:1") == "http://localhost:1"
    assert check_url("http://[::1]:8000") == "http://[::1]:8000"


@pytest.mark.parametrize(
    "data",
    [None, [], "allow", {"decision": "ALLOW"}, {"decision": "maybe"}, {"reason": "x"}],
)
def test_malformed_answers_are_deny(data: object) -> None:
    assert parse_answer(data).decision is Decision.DENY


def test_parse_answer_drops_bad_ids() -> None:
    answer = parse_answer(
        {"decision": "require_approval", "reason": 5, "approval_id": "x", "action_hash": "z"}
    )
    assert answer == Answer(Decision.REQUIRE_APPROVAL, "no reason given")


class _Fake(http.server.BaseHTTPRequestHandler):
    status = 200
    body = b""
    extra: dict[str, str] = {}

    def do_POST(self) -> None:  # noqa: N802 (http.server's naming)
        self.send_response(self.status)
        for name, value in self.extra.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def fake() -> Iterator[tuple[type[_Fake], str]]:
    handler = type("Handler", (_Fake,), {})
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_error_status_saying_allow_is_still_deny(fake: tuple[type[_Fake], str]) -> None:
    handler, url = fake
    handler.status, handler.body = 500, b'{"decision": "allow", "reason": "lol"}'
    answer = WardenClient(url).evaluate("read_file", {})
    assert answer == Answer(Decision.DENY, "Warden returned HTTP 500")


def test_error_status_without_reason(fake: tuple[type[_Fake], str]) -> None:
    handler, url = fake
    handler.status, handler.body = 502, b"<html>bad gateway</html>"
    assert WardenClient(url).evaluate("read_file", {}).reason == "unexpected answer from Warden"
    handler.body = b'{"decision": "deny"}'
    assert WardenClient(url).evaluate("read_file", {}).reason == "HTTP 502"


def test_huge_answer_is_deny(fake: tuple[type[_Fake], str]) -> None:
    handler, url = fake
    handler.body = b'{"decision": "allow", "reason": "' + b"x" * 70_000 + b'"}'
    assert WardenClient(url).evaluate("read_file", {}).decision is Decision.DENY


def test_garbage_answer_is_deny(fake: tuple[type[_Fake], str]) -> None:
    handler, url = fake
    handler.body = b"not json"
    assert WardenClient(url).evaluate("read_file", {}).decision is Decision.DENY


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ({"Retry-After": "7"}, 7.0),
        ({"Retry-After": "9999"}, 60.0),
        ({"Retry-After": "x"}, 1.0),
        ({}, 1.0),
        ({"Retry-After": "0"}, 1.0),
    ],
)
def test_rate_limited_answer_carries_retry_after(
    fake: tuple[type[_Fake], str], header: dict[str, str], expected: float
) -> None:
    handler, url = fake
    handler.status, handler.extra = 429, header
    handler.body = b'{"decision": "deny", "reason": "rate limit exceeded"}'
    answer = WardenClient(url).evaluate("read_file", {})
    assert answer.decision is Decision.DENY and not answer.allowed
    assert answer.retry_after == expected


@pytest.mark.parametrize("var", ["http_proxy", "HTTP_PROXY", "all_proxy"])
def test_proxy_settings_are_ignored(url: str, var: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # A proxy would receive the tool arguments and could answer "allow" itself.
    monkeypatch.setenv(var, "http://127.0.0.1:9")  # nothing listens there
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert WardenClient(url, "agent-1").evaluate("read_file", {"path": "/a"}).allowed
