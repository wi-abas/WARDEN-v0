"""Shared test helpers."""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

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


def shown_hashes(store: Any, ids: list[str]) -> list[str]:
    """The action_hash a human would have been shown for each id (as `warden approvals`
    sends them). Unknown ids get a dummy hash: they fail as "not found" anyway."""
    return [store._items[i].action_hash if i in store._items else "0" * 64 for i in ids]


def shown(client: Any, approval_id: str, headers: dict[str, str]) -> dict[str, str]:
    """The body a human sends to /approve or /deny after listing: {"action_hash": the
    hash the list showed}. {} when it isn't listed (not pending): revoking an approved
    approval needs no hash, and anything else is refused before the hash matters."""
    items = client.get("/v1/approvals", headers=headers, params={"ids": approval_id}).json()
    return {"action_hash": items[0]["action_hash"]} if items else {}


class Clock[T]:
    """A clock tests move by hand (`clock.now += 5`), passed where code wants time.time."""

    def __init__(self, start: T) -> None:
        self.now = start

    def __call__(self) -> T:
        return self.now
