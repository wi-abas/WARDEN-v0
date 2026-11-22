"""Re-audit of the features built in the long build session: fuzzing and races.

- Proxy: random JSON-RPC traffic never gets an unchecked or modified tools/call through.
- SDK: whatever the arguments and however they're changed, the tool runs with exactly
  what Warden checked.
- Nested conditions: a deny rule on a nested value can't be dodged.
- Races: one approval gives one allow (with persistence, many threads); rate limits
  hold under concurrent requests.
"""

import asyncio
import json
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from helpers import ADMIN_KEY, live_server
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import JsonValue

from warden.api import create_app
from warden.approvals import ApprovalDB, ApprovalStore, Status
from warden.audit import SQLiteAuditLog
from warden.client import Answer
from warden.engine import evaluate
from warden.mcp_proxy import PASS_THROUGH, TOOL_CALL_PARAMS, McpProxy, ProxyConfig
from warden.models import ActionRequest, Decision
from warden.policy import parse_policy
from warden.sdk import WardenClient, guard

FAST = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])

json_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(10**20), 10**20),
    st.text(max_size=8),
    st.floats(allow_nan=False, allow_infinity=False),
)
json_values = st.recursive(
    json_leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(st.text(max_size=6), children, max_size=4)
    ),
    max_leaves=12,
)


# --- Proxy fuzzing --------------------------------------------------------------------


class Gatekeeper:
    """Allows only tool "safe" with {"ok": true}; records what it allowed."""

    def __init__(self) -> None:
        self.allowed: list[tuple[str, str]] = []

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        if tool == "safe" and arguments == {"ok": True}:
            self.allowed.append((tool, json.dumps(arguments, sort_keys=True)))
            return Answer(Decision.ALLOW, "ok")
        return Answer(Decision.DENY, "no")


methods = st.sampled_from(
    [
        "tools/call",
        "tools/call ",
        "TOOLS/CALL",
        "tools/Call",
        "tools/call​",
        "ping",
        "initialize",
        "resources/read",
        "prompts/get",
        "notifications/initialized",
        "notifications/tools/call",
        "sampling/createMessage",
        "",
    ]
) | st.text(max_size=12)

messages = st.fixed_dictionaries(
    {},
    optional={
        "jsonrpc": st.sampled_from(["2.0", "1.0", 2.0]),
        "id": st.one_of(st.none(), st.integers(), st.text(max_size=4), st.booleans(), st.floats()),
        "method": methods,
        "params": st.one_of(
            json_values,
            st.fixed_dictionaries(
                {"name": st.sampled_from(["safe", "danger", "safe "])},
                optional={
                    "arguments": st.one_of(
                        st.just({"ok": True}), st.just({"ok": True, "x": 1}), json_values
                    ),
                    "_meta": json_values,
                    "extra": json_values,
                },
            ),
        ),
        "result": json_values,
    },
)


def run_proxy_on(lines: list[bytes]) -> tuple[list[dict[str, Any]], Gatekeeper]:
    gate = Gatekeeper()
    forwarded: list[dict[str, Any]] = []

    async def main() -> None:
        config = ProxyConfig.model_validate({"server": {"command": "x"}}, strict=False)
        proxy = McpProxy(config, gate, asyncio.Queue().get, lambda data: None)

        async def capture(message: dict[str, Any]) -> None:
            forwarded.append(json.loads(json.dumps(message)))

        proxy._forward = capture  # type: ignore[method-assign]
        for line in lines:
            await proxy._handle(line)
        while proxy._calls:
            await asyncio.gather(*proxy._calls.values(), return_exceptions=True)

    asyncio.run(main())
    return forwarded, gate


def assert_only_safe_traffic(forwarded: list[dict[str, Any]], gate: Gatekeeper) -> None:
    calls = 0
    for message in forwarded:
        method = message.get("method")
        if method == "tools/call":
            calls += 1
            params = message["params"]
            assert "id" in message and set(params) <= TOOL_CALL_PARAMS
            assert params["name"] == "safe" and params.get("arguments") == {"ok": True}
        elif method is not None and "id" in message:
            assert method in PASS_THROUGH  # no allow_methods configured
        elif method is not None:
            assert method.startswith("notifications/")
        else:  # forwarded without a method: must be a plain response, nothing more
            assert "method" not in message
            assert set(message) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
    assert calls == len(gate.allowed)


@FAST
@given(st.lists(messages, max_size=6))
def test_proxy_never_forwards_an_unchecked_tool_call(batch: list[dict[str, Any]]) -> None:
    forwarded, gate = run_proxy_on([json.dumps(m).encode() for m in batch])
    assert_only_safe_traffic(forwarded, gate)


@FAST
@given(st.sampled_from(["method", "name", "arguments", "ok", "params", "jsonrpc", "id"]))
def test_proxy_refuses_every_duplicate_key_trick(key: str) -> None:
    lines = [
        b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":'
        b'{"name":"danger","arguments":{}}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger",'
        b'"name":"safe","arguments":{"ok":true}}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe",'
        b'"arguments":{"ok":false,"ok":true}}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe",'
        b'"arguments":{"ok":true}},"params":{"name":"danger"}}',
        f'{{"jsonrpc":"2.0","id":1,"{key}":1,"{key}":2,"method":"ping"}}'.encode(),
    ]
    forwarded, gate = run_proxy_on(lines)
    assert forwarded == [] and gate.allowed == []


# --- SDK: checked == executed ---------------------------------------------------------


class Recorder(WardenClient):
    def __init__(self, tamper: Any) -> None:
        super().__init__()
        self.checked: list[str] = []
        self.tamper = tamper

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        self.checked.append(json.dumps(arguments, sort_keys=True))
        self.tamper()
        return Answer(Decision.ALLOW, "ok")


def scramble(value: Any) -> None:
    """Change every mutable container inside `value`, in place."""
    if isinstance(value, dict):
        for key in list(value):
            scramble(value[key])
            value[key] = "tampered"
        value["injected"] = "/etc/passwd"
    elif isinstance(value, list):
        for item in value:
            scramble(item)
        value.append("tampered")


@FAST
@given(st.dictionaries(st.from_regex(r"[a-z]{1,6}", fullmatch=True), json_values, max_size=5))
def test_sdk_runs_exactly_what_was_checked(arguments: dict[str, Any]) -> None:
    client = Recorder(tamper=lambda: scramble(arguments))
    received: list[str] = []

    @guard("tool", client=client)
    def tool(**kwargs: Any) -> None:
        received.append(json.dumps(kwargs, sort_keys=True))

    original = json.dumps(arguments, sort_keys=True)
    tool(**arguments)
    assert received == client.checked == [original]


# --- Nested conditions can't be dodged ------------------------------------------------

NESTED = parse_policy(
    json.dumps(
        {
            "rules": [
                {"id": "ok", "tool": "send", "effect": "allow"},
                {
                    "id": "no-evil",
                    "tool": "send",
                    "effect": "deny",
                    "when": [
                        {
                            "arg": "msg.headers.to",
                            "op": "endswith",
                            "value": "@evil.net",
                            "ignore_case": True,
                        }
                    ],
                },
            ]
        }
    )
).rules

recipients = st.sampled_from(
    [
        "a@evil.net",
        "A@EVIL.NET",
        "a@evil.net ",
        "a@evil.net.",
        "Evil <a@evil.net>",
        "b@good.com, a@evil.net",
        "a@evi​l.net",
        "a@ｅvil.net",
        "a@evil。net",
        "a@good.com",
    ]
)
nested_args = st.recursive(
    st.one_of(json_leaf, recipients),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.sampled_from(["msg", "headers", "to", "cc", "x"]), children, max_size=3),
    ),
    max_leaves=10,
)


@settings(max_examples=2000, deadline=None)
@given(st.dictionaries(st.sampled_from(["msg", "headers", "to"]), nested_args, max_size=3))
def test_nested_deny_rule_cant_be_dodged(arguments: dict[str, Any]) -> None:
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "send", "arguments": arguments}
    )
    result = evaluate(request, NESTED)
    if result.decision is not Decision.ALLOW:
        return
    # Allowed: the path must exist all the way down and end in a harmless plain address.
    value: Any = arguments
    for key in ("msg", "headers", "to"):
        assert isinstance(value, dict) and key in value
        value = value[key]
    assert isinstance(value, str) and not value.casefold().endswith("@evil.net")


# --- Races ----------------------------------------------------------------------------


def post(url: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[int, Any]:
    request = urllib.request.Request(  # noqa: S310 (local test server)
        f"{url}/v1/evaluate",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def test_one_persistent_approval_gives_exactly_one_allow_under_a_race(tmp_path: Path) -> None:
    policy = tmp_path / "p.json"
    policy.write_text(
        json.dumps({"rules": [{"id": "s", "tool": "send", "effect": "require_approval"}]})
    )
    db = tmp_path / "audit.db"
    app = create_app(
        policy,
        audit_log=SQLiteAuditLog(db),
        approvals=ApprovalStore(db=ApprovalDB(db)),
        admin_key=ADMIN_KEY,
    )
    body = {"agent_id": "a", "tool": "send", "arguments": {"to": "x"}}
    with live_server(app) as url:
        first = post(url, body)[1]
        approval_id, action_hash = first["approval_id"], first["action_hash"]
        approve = urllib.request.Request(  # noqa: S310
            f"{url}/v1/approvals/{approval_id}/approve",
            method="POST",
            headers={"X-Warden-Admin-Key": ADMIN_KEY},
        )
        urllib.request.urlopen(approve, timeout=10).close()  # noqa: S310
        barrier = threading.Barrier(24)

        def attempt(_: int) -> str:
            barrier.wait()
            return str(post(url, {**body, "approval_id": approval_id})[1]["decision"])

        with ThreadPoolExecutor(24) as pool:
            decisions = list(pool.map(attempt, range(24)))
    assert decisions.count("allow") == 1
    assert decisions.count("deny") == 23
    # And after a "restart", it stays used.
    store = ApprovalStore(db=ApprovalDB(db))
    assert store.use(approval_id, action_hash, agent_id="a") is Status.USED


def test_rate_limit_holds_under_concurrent_requests(tmp_path: Path) -> None:
    policy = tmp_path / "p.json"
    policy.write_text(
        json.dumps(
            {
                "rules": [{"id": "r", "tool": "read", "effect": "allow"}],
                "limits": {"default": {"requests_per_minute": 30}},
            }
        )
    )
    app = create_app(policy, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=ADMIN_KEY)
    body = {"agent_id": "a", "tool": "read", "arguments": {}}
    with live_server(app) as url:
        barrier = threading.Barrier(20)

        def burst(_: int) -> list[int]:
            barrier.wait()
            return [post(url, body)[0] for _ in range(4)]

        with ThreadPoolExecutor(20) as pool:
            codes = [c for batch in pool.map(burst, range(20)) for c in batch]
    # 30 per minute = a burst of 30; the test takes well under the 2 s a new token needs.
    assert codes.count(200) == 30
    assert codes.count(429) == 50


def test_fuzz_harness_sees_allowed_calls() -> None:
    """The fuzz assertion isn't vacuous: a real allowed call is forwarded and counted."""
    good = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "safe", "arguments": {"ok": True}},
    }
    bad = {**good, "id": 2, "params": {"name": "safe", "arguments": {"ok": True}, "extra": 1}}
    forwarded, gate = run_proxy_on([json.dumps(good).encode(), json.dumps(bad).encode()])
    assert len(forwarded) == 1 and len(gate.allowed) == 1
    assert_only_safe_traffic(forwarded, gate)


def test_messages_shaped_like_calls_without_a_method_are_refused() -> None:
    lines = [
        b'{"jsonrpc":"2.0","id":1,"method":null,"params":{"name":"danger","arguments":{}}}',
        b'{"jsonrpc":"2.0","id":2,"params":{"name":"danger","arguments":{}}}',
        b'{"jsonrpc":"2.0","id":3,"result":{},"params":{"name":"danger"}}',
        b'{"jsonrpc":"2.0","id":4,"result":{},"error":{}}',
    ]
    forwarded, _ = run_proxy_on(lines)
    assert forwarded == []
    ok, _ = run_proxy_on([b'{"jsonrpc":"2.0","id":"s1","result":{"roots":[]}}'])
    assert ok == [{"jsonrpc": "2.0", "id": "s1", "result": {"roots": []}}]
