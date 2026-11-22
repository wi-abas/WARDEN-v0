"""How much time does Warden add per tool call?

Run:  uv run python scripts/benchmark.py

Measures (1) the decision alone, in-process, (2) a full HTTP request to a real
local server, including the (hash-chained) audit-log write to SQLite, and (3) an MCP
tools/call straight to a small stdio server vs. through `warden proxy`. Numbers depend
on your machine.
"""

import asyncio
import json
import statistics
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import uvicorn

from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.client import WardenClient
from warden.engine import evaluate
from warden.mcp_proxy import McpProxy, ProxyConfig
from warden.models import ActionRequest
from warden.policy import DEFAULT_POLICY_PATH, load_policy

REQUEST = {
    "agent_id": "bench",
    "tool": "send_email",
    "arguments": {"to": "bob@example.com", "subject": "hi"},
}


def percentiles(samples_ms: list[float]) -> str:
    q = statistics.quantiles(samples_ms, n=100)
    return f"median {statistics.median(samples_ms):.3f} ms, p95 {q[94]:.3f} ms, p99 {q[98]:.3f} ms"


def bench_engine(n: int = 20_000) -> str:
    policy = load_policy(DEFAULT_POLICY_PATH)
    request = ActionRequest.model_validate(REQUEST)
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        evaluate(request, policy.rules, policy.tools)
        samples.append((time.perf_counter() - start) * 1000)
    return percentiles(samples)


FAKE_MCP_SERVER = Path(__file__).parent.parent / "tests" / "fixtures" / "fake_mcp_server.py"


def _start(policy: Path, audit_db: Path) -> tuple[uvicorn.Server, threading.Thread, int]:
    app = create_app(policy, audit_log=SQLiteAuditLog(audit_db), admin_key="bench-" + "x" * 32)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    return server, thread, server.servers[0].sockets[0].getsockname()[1]


# The default per-agent limit (1,200/minute) would stop a benchmark: lift it here.
NO_LIMIT = {"default": {"requests_per_minute": 100_000}}


def bench_http(n: int = 2_000) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        policy = Path(tmp) / "policy.json"
        data = json.loads(DEFAULT_POLICY_PATH.read_text())
        policy.write_text(json.dumps({**data, "limits": NO_LIMIT}))
        server, thread, port = _start(policy, Path(tmp) / "audit.db")
        body = json.dumps(REQUEST).encode()
        samples = []
        for _ in range(n):
            request = urllib.request.Request(  # noqa: S310 (local server)
                f"http://127.0.0.1:{port}/v1/evaluate",
                data=body,
                headers={"content-type": "application/json"},
            )
            start = time.perf_counter()
            with urllib.request.urlopen(request) as response:  # noqa: S310
                response.read()
            samples.append((time.perf_counter() - start) * 1000)
        server.should_exit = True
        thread.join(timeout=5)
    return percentiles(samples)


def _call(i: int) -> bytes:
    message = {
        "jsonrpc": "2.0",
        "id": i,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"path": "/workspace/a.txt"}},
    }
    return json.dumps(message).encode() + b"\n"


async def _direct(n: int) -> list[float]:
    """tools/call straight to the stdio server (the baseline)."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(FAKE_MCP_SERVER),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None  # noqa: S101
    samples = []
    for i in range(n):
        start = time.perf_counter()
        process.stdin.write(_call(i))
        await process.stdin.drain()
        await process.stdout.readline()
        samples.append((time.perf_counter() - start) * 1000)
    process.stdin.close()
    await process.wait()
    return samples


async def _proxied(n: int, url: str) -> list[float]:
    """The same calls through warden proxy (checked by a real Warden server)."""
    config = ProxyConfig.model_validate(
        {"server": {"command": sys.executable, "args": [str(FAKE_MCP_SERVER)]}}, strict=False
    )
    inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
    outbox: asyncio.Queue[bytes] = asyncio.Queue()
    proxy = McpProxy(config, WardenClient(url, "bench"), inbox.get, outbox.put_nowait)
    running = asyncio.create_task(proxy.run())
    samples = []
    for i in range(n):
        start = time.perf_counter()
        inbox.put_nowait(_call(i))
        await outbox.get()
        samples.append((time.perf_counter() - start) * 1000)
    inbox.put_nowait(b"")
    await running
    return samples


def bench_proxy(n: int = 1_000) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        policy = Path(tmp) / "policy.json"
        rules = [{"id": "ok", "tool": "echo", "effect": "allow"}]
        policy.write_text(json.dumps({"rules": rules, "limits": NO_LIMIT}))
        server, thread, port = _start(policy, Path(tmp) / "audit.db")
        direct = asyncio.run(_direct(n))
        proxied = asyncio.run(_proxied(n, f"http://127.0.0.1:{port}"))
        server.should_exit = True
        thread.join(timeout=5)
    return percentiles(direct), percentiles(proxied)


if __name__ == "__main__":
    print("Decision only (in-process):     ", bench_engine())
    print("Full HTTP request + audit write:", bench_http())
    direct, proxied = bench_proxy()
    print("MCP tools/call, direct:         ", direct)
    print("MCP tools/call, through proxy:  ", proxied)
