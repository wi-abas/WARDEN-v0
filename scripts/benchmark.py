"""How much time does Warden add per tool call?

Run:  uv run python scripts/benchmark.py

Measures (1) the decision alone, in-process, and (2) a full HTTP request to a real
local server, including the audit-log write to SQLite. Numbers depend on your machine.
"""

import json
import statistics
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import uvicorn

from warden.api import create_app
from warden.audit import SQLiteAuditLog
from warden.engine import evaluate
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


def bench_http(n: int = 2_000) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(
            DEFAULT_POLICY_PATH,
            audit_log=SQLiteAuditLog(Path(tmp) / "audit.db"),
            admin_key="bench-" + "x" * 32,
        )
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        while not server.started:
            time.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
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


if __name__ == "__main__":
    print("Decision only (in-process):     ", bench_engine())
    print("Full HTTP request + audit write:", bench_http())
