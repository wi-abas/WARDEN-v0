"""Fuzz targets: each takes raw bytes and fails (raises) only on a real bug.

Expected rejections (invalid input, deny) are fine. Each target checks an invariant
with an independent oracle, so it finds wrong answers, not just crashes:

- policy:   parsing any text either works or raises the documented errors.
- evaluate: any request body either fails validation or gets a deterministic answer;
            "allow" only ever comes from an allow rule for that very tool.
- bypass:   if Warden allows a path / URL / email, a plain standard-library check
            agrees it's inside /workspace/, on api.example.com, or @example.com.
- proxy:    nothing reaches the MCP server unless it's a checked-and-allowed
            tools/call with exactly the checked name and arguments, an allowed method,
            a notification, or a well-formed response.
- http:     the HTTP API never answers 5xx and every error carries "deny".

Run locally through Hypothesis (tests/test_fuzz_targets.py) or with coverage guidance
through Atheris (scripts/fuzz.py, Linux CI).
"""

import asyncio
import json
import posixpath
import tempfile
import unicodedata
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import JsonValue, ValidationError

from warden.client import Answer
from warden.engine import evaluate
from warden.mcp_proxy import PASS_THROUGH, TOOL_CALL_PARAMS, McpProxy, ProxyConfig
from warden.models import ActionRequest, Decision
from warden.policy import DuplicateKeyError, no_duplicate_keys, parse_policy

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = parse_policy((ROOT / "policies" / "default.json").read_text())

BYPASS_POLICY = parse_policy(
    json.dumps(
        {
            "rules": [
                {
                    "id": "ws",
                    "tool": "read",
                    "effect": "allow",
                    "when": [{"arg": "path", "op": "startswith", "value": "/workspace/"}],
                },
                {
                    "id": "api",
                    "tool": "fetch",
                    "effect": "allow",
                    "when": [{"arg": "url", "op": "host_in", "value": ["api.example.com"]}],
                },
                {
                    "id": "mail",
                    "tool": "mail",
                    "effect": "allow",
                    "when": [
                        {
                            "arg": "to",
                            "op": "endswith",
                            "value": "@example.com",
                            "ignore_case": True,
                        }
                    ],
                },
            ]
        }
    )
)


def text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


# --- policy --------------------------------------------------------------------------


def fuzz_policy(data: bytes) -> None:
    try:
        policy = parse_policy(text(data))
    except (ValidationError, DuplicateKeyError):
        return
    # A policy that loaded must evaluate without raising, for any tool it names.
    for rule in policy.rules:
        request = ActionRequest(agent_id="fuzz", tool=rule.tool, arguments={})
        evaluate(request, policy.rules, policy.tools)


# --- evaluate ------------------------------------------------------------------------


def fuzz_evaluate(data: bytes) -> None:
    try:
        request = ActionRequest.model_validate_json(data)
    except ValidationError:
        return
    first = evaluate(request, DEFAULT_POLICY.rules, DEFAULT_POLICY.tools)
    second = evaluate(request, DEFAULT_POLICY.rules, DEFAULT_POLICY.tools)
    assert first == second, "evaluation isn't deterministic"
    if first.decision is Decision.ALLOW:
        rules = {r.id: r for r in DEFAULT_POLICY.rules}
        rule = rules.get(first.matched_rule or "")
        assert rule is not None, "allow without a matched rule"
        assert rule.effect is Decision.ALLOW and rule.tool == request.tool, "allow from wrong rule"


# --- bypass oracles ------------------------------------------------------------------


def _plain(value: str) -> bool:
    """No invisible or control characters, look-alikes, escapes or whitespace tricks.
    (Unassigned code points are fine: they can't move a path or change a host.)"""
    hidden = {"Cc", "Cf", "Cs", "Zl", "Zp"}
    return (
        not any(unicodedata.category(ch) in hidden for ch in value)
        # No compatibility look-alikes (full-width letters, look-alike dots). Canonical
        # composition (B + combining mark) is fine: it's the same text.
        and unicodedata.normalize("NFKC", value) == unicodedata.normalize("NFC", value)
        and unquote(value) == value
        and value == value.strip()
    )


def _path_is_inside(path: str) -> bool:
    def inside(p: str) -> bool:
        normal = posixpath.normpath(p) + ("/" if p.endswith("/") else "")
        return p.startswith("/workspace/") and normal == p

    return (
        _plain(path)
        and inside(path)
        and inside(unicodedata.normalize("NFC", path))  # e.g. what macOS stores
        and inside(unicodedata.normalize("NFD", path))
        and "\\" not in path
        and "\x00" not in path
    )


def _authority_host(url: str) -> str | None:
    """The host as a careful, simple reader sees it: after "//", before / ? # \\,
    without user info or port. None if the URL doesn't have that shape."""
    if "://" not in url:
        return None
    rest = url.split("://", 1)[1]
    for stop in "/?#\\":
        rest = rest.split(stop, 1)[0]
    host = rest.rsplit("@", 1)[-1]
    if host.startswith("["):
        return None
    return host.rsplit(":", 1)[0].lower()


def _url_is_on_api(url: str) -> bool:
    parts = urlsplit(url)
    return (
        _plain(url)
        and parts.hostname == "api.example.com"
        and _authority_host(url) == "api.example.com"
    )


def _email_is_at_example(address: str) -> bool:
    return (
        _plain(address)
        and address.count("@") == 1
        # No routing tricks before "@" (percent hack, bang paths, groups, quoting).
        and not any(ch in "%!:\\" for ch in address.rsplit("@", 1)[0])
        # The part before "@" may be non-English (SMTPUTF8); the domain may not.
        and address.rsplit("@", 1)[1].isascii()
        and address.rsplit("@", 1)[1].lower() == "example.com"
        and parseaddr(address)[1] == address
        and " " not in address
        and "," not in address
    )


def fuzz_bypass(data: bytes) -> None:
    if not data:
        return
    kind, value = data[0] % 3, text(data[1:])
    tool, arg, prefix, oracle = [
        ("read", "path", "/workspace/", _path_is_inside),
        ("fetch", "url", "https://api.example.com", _url_is_on_api),
        ("mail", "to", "bob", _email_is_at_example),
    ][kind]
    # Half the time start from a valid value, so the fuzzer explores near the edge.
    if data[0] & 4:
        value = prefix + value
    if kind == 2 and data[0] & 8:
        value = value + "@example.com"
    request = ActionRequest(agent_id="fuzz", tool=tool, arguments={arg: value})
    result = evaluate(request, BYPASS_POLICY.rules, BYPASS_POLICY.tools)
    if result.decision is Decision.ALLOW:
        assert oracle(value), f"bypass: {tool} allowed {value!r}"


# --- proxy ---------------------------------------------------------------------------


class _Checker:
    def __init__(self) -> None:
        self.allowed: list[tuple[str, Any]] = []

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        if "danger" in tool:
            return Answer(Decision.DENY, "no")
        self.allowed.append((tool, json.loads(json.dumps(arguments))))
        return Answer(Decision.ALLOW, "ok")


class _Writer:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.sent.append(data)

    async def drain(self) -> None:
        return None

    def is_closing(self) -> bool:
        return False


_PROXY_CONFIG = ProxyConfig.model_validate(
    {"server": {"command": "unused"}, "approval": {"mode": "error"}}, strict=False
)


def _check_forwarded(line: bytes, checker: _Checker) -> None:
    assert line.endswith(b"\n") and line.count(b"\n") == 1, "forwarded more than one line"
    message = json.loads(line, object_pairs_hook=no_duplicate_keys)
    assert isinstance(message, dict), "forwarded a non-object"
    method = message.get("method")
    if method == "tools/call":
        params = message["params"]
        assert set(params) <= TOOL_CALL_PARAMS, "forwarded unchecked params"
        name, arguments = params["name"], params.get("arguments", {})
        assert (name, arguments) in checker.allowed, "forwarded an unchecked tools/call"
    elif method is not None:
        assert isinstance(method, str)
        assert method in PASS_THROUGH or (
            method.startswith("notifications/") and "id" not in message
        ), f"forwarded method {method!r}"
    else:
        assert set(message) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"}), (
            "forwarded a malformed response"
        )


def fuzz_proxy(data: bytes) -> None:
    checker, writer = _Checker(), _Writer()
    replies: list[bytes] = []

    async def run() -> None:
        proxy = McpProxy(_PROXY_CONFIG, checker, _never, replies.append)
        proxy._server_in = writer  # type: ignore[assignment]
        for line in data.split(b"\n")[:20]:
            if line.strip():
                await proxy._handle(line)
        await asyncio.gather(*proxy._calls.values())

    asyncio.run(run())
    for line in writer.sent:
        _check_forwarded(line, checker)
    for reply in replies:
        json.loads(reply)  # every answer to the client is valid JSON


async def _never() -> bytes | None:  # pragma: no cover - _handle is driven directly
    return b""


# --- http ----------------------------------------------------------------------------

_client: Any = None


def _http_client() -> Any:
    global _client
    if _client is None:
        from fastapi.testclient import TestClient

        import warden.api
        from warden.api import create_app
        from warden.audit import SQLiteAuditLog

        warden.api.ALLOWED_HOSTS = (*warden.api.ALLOWED_HOSTS, "testserver")
        warden.api.RECORD_REJECTIONS_IN_BACKGROUND = False
        folder = Path(tempfile.mkdtemp())
        policy = json.loads((ROOT / "policies" / "default.json").read_text())
        # No rate limit: the fuzzer sends far more than 1,200 requests a minute.
        policy["limits"] = {"default": {"requests_per_minute": 100_000}}
        (folder / "policy.json").write_text(json.dumps(policy))
        db = folder / "fuzz-audit.db"
        app = create_app(
            folder / "policy.json",
            audit_log=SQLiteAuditLog(db, retention_days=None),
            admin_key="fuzz-admin-key-0123456789abcdef0123",
        )
        _client = TestClient(app, raise_server_exceptions=False)
    return _client


def fuzz_http(data: bytes) -> None:
    response = _http_client().post(
        "/v1/evaluate", content=data, headers={"content-type": "application/json"}
    )
    assert response.status_code < 500, f"HTTP {response.status_code}"
    if response.status_code != 200:
        assert response.json()["decision"] == "deny", "error without deny"


TARGETS = {
    "policy": fuzz_policy,
    "evaluate": fuzz_evaluate,
    "bypass": fuzz_bypass,
    "proxy": fuzz_proxy,
    "http": fuzz_http,
}
