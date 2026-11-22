"""A locked audit database must never freeze the whole server."""

import sqlite3
import threading
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI
from helpers import BASIC_POLICY

import warden.api
from warden.api import create_app
from warden.audit import SQLiteAuditLog


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[FastAPI, str, Path]]:
    monkeypatch.setattr(warden.api, "RECORD_REJECTIONS_IN_BACKGROUND", True)  # the real setting
    db = tmp_path / "a.db"
    app = create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(db), admin_key="k" * 32)
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="critical"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.01)
    port = srv.servers[0].sockets[0].getsockname()[1]
    yield app, f"http://127.0.0.1:{port}", db
    srv.should_exit = True
    thread.join(timeout=10)


def _get(url: str, host: str | None = None) -> int:
    request = urllib.request.Request(url, headers={"Host": host} if host else {})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as error:
        return error.code


def test_rejections_while_the_db_is_locked_do_not_freeze_the_server(
    server: tuple[FastAPI, str, Path],
) -> None:
    app, url, db = server
    lock = sqlite3.connect(db, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")  # another program holds the database
    try:
        for _ in range(3):  # rejected requests whose records must wait for the lock
            assert _get(f"{url}/health", host="evil.example.com") == 400
        started = time.monotonic()
        assert _get(f"{url}/health") == 200
        assert time.monotonic() - started < 1.0  # was 5+ seconds before the fix
    finally:
        lock.execute("ROLLBACK")
        lock.close()
    app.state.warden.flush_events()
    log = SQLiteAuditLog(db, retention_days=None)
    assert len(log.recent_events()) == 3  # recorded once the lock was released
