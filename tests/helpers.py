"""Shared test helpers."""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI

# A small, fixed policy for tests (allow read_file, approve send_email, deny delete_file).
# Tests use this instead of policies/default.json, so the default can evolve freely.
BASIC_POLICY = Path(__file__).parent / "fixtures" / "basic-policy.json"
ADMIN_KEY = "test-admin-key-0123456789"


@contextmanager
def live_server(app: FastAPI) -> Iterator[str]:
    """Run `app` on a real local port in a thread; yields its base URL."""
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
