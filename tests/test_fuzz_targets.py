"""Run the fuzz targets (tests/fuzz_targets.py) through Hypothesis on every test run.

Atheris (scripts/fuzz.py) runs the same targets with coverage guidance in CI. Here,
Hypothesis feeds random bytes plus JSON-shaped and near-valid inputs, so a broken
invariant fails the normal test suite too. HYPOTHESIS_PROFILE=deep runs many more.
"""

import json
import os

import pytest
from fuzz_targets import TARGETS
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

EXAMPLES = 5000 if os.environ.get("HYPOTHESIS_PROFILE") == "deep" else 150
FUZZ = settings(
    max_examples=EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=12,
)
TOOLS = ["read_file", "write_file", "delete_file", "send_email", "tools/call", "x"]
KEYS = ["agent_id", "tool", "arguments", "approval_id", "path", "to", "bcc", "content"]


@st.composite
def requests(draw: st.DrawFn) -> bytes:
    """Near-valid /v1/evaluate bodies, so the fuzzer gets past validation."""
    body: dict[str, object] = {"agent_id": draw(st.sampled_from(["a", "agent-1", ""]))}
    body["tool"] = draw(st.sampled_from(TOOLS))
    body["arguments"] = draw(st.dictionaries(st.sampled_from(KEYS), json_values, max_size=3))
    return json.dumps(body).encode()


@st.composite
def mcp_lines(draw: st.DrawFn) -> bytes:
    """Near-valid MCP messages, joined into one session."""
    lines = []
    for _ in range(draw(st.integers(1, 5))):
        message: dict[str, object] = {"jsonrpc": draw(st.sampled_from(["2.0", "1.0"]))}
        if draw(st.booleans()):
            message["id"] = draw(st.one_of(st.integers(), st.text(max_size=4), json_values))
        if draw(st.booleans()):
            message["method"] = draw(
                st.sampled_from(
                    ["tools/call", "tools/list", "resources/read", "notifications/x", "ping"]
                )
                | st.text(max_size=12)
            )
        for key in draw(st.lists(st.sampled_from(["params", "result", "error", "x"]), max_size=2)):
            message[key] = draw(json_values)
        if message.get("method") == "tools/call" and draw(st.booleans()):
            message["params"] = {
                "name": draw(st.sampled_from(["echo", "danger", "x.y"])),
                "arguments": draw(st.dictionaries(st.text(max_size=4), json_values, max_size=3)),
            }
        lines.append(json.dumps(message))
    return "\n".join(lines).encode()


INPUTS = {
    "policy": st.binary(max_size=2000) | json_values.map(lambda v: json.dumps(v).encode()),
    "evaluate": st.binary(max_size=500) | requests(),
    "bypass": st.binary(max_size=200),
    "proxy": st.binary(max_size=500) | mcp_lines(),
    "http": st.binary(max_size=500) | requests(),
}


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_fuzz_target(name: str) -> None:
    target = TARGETS[name]

    @FUZZ
    @given(INPUTS[name])
    def run(data: bytes) -> None:
        target(data)

    run()


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("bypass", b"\x04../etc/passwd"),
        ("bypass", b"\x04%2e%2e/etc"),
        ("bypass", b"\x05.evil.net/"),
        ("bypass", b"\x05@evil.net/"),
        ("bypass", b"\x0e@evil.net, x"),
        ("proxy", b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger"}}'),
        ("proxy", b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"e","x":1}}'),
        ("proxy", b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}'),
        ("proxy", b'{"jsonrpc":"2.0","id":1,"params":{"name":"echo"}}'),
        ("http", b"[" * 30000 + b"]" * 30000),
        ("http", b'{"tool":"a","tool":"b"}'),
    ],
)
def test_known_tricky_inputs(name: str, data: bytes) -> None:
    TARGETS[name](data)


def test_oracles_catch_a_bypass() -> None:
    """The oracles must actually say no to bad values, or the fuzzer proves nothing."""
    from fuzz_targets import _email_is_at_example, _path_is_inside, _url_is_on_api

    assert _path_is_inside("/workspace/a.txt")
    for bad in ["/workspace/../etc", "/workspace/%2e%2e/x", "/etc/x", "/workspace/a​"]:
        assert not _path_is_inside(bad)
    assert _url_is_on_api("https://api.example.com/v1")
    for bad in ["https://api.example.com.evil.net/", "https://x@evil.net/", "http://evil"]:
        assert not _url_is_on_api(bad)
    assert _email_is_at_example("bob@example.com")
    for bad in ["x@evil.net", "a@example.com, b@evil.net", "Bob <b@example.com>"]:
        assert not _email_is_at_example(bad)
