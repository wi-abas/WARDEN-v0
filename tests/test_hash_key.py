"""The action_hash is keyed with a per-install secret (docs/design/keyed-action-hash.md):
a copy of the database alone doesn't let anyone guess arguments from stored hashes."""

import hashlib
import hmac
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY

import warden.api
from warden.api import StartupError, create_app
from warden.approvals import ApprovalDB, ApprovalStore
from warden.audit import SQLiteAuditLog
from warden.fingerprint import FINGERPRINT_VERSION, canonical_json, fingerprint
from warden.hash_key import HashKeyError, key_path_for, load_or_create
from warden.models import ActionRequest
from warden.settings import Settings

POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
REQUEST = ActionRequest.model_validate(
    {"agent_id": "billing", "tool": "send_invoice", "arguments": {"amount": 48213}}
)


# --- The keyed hash ------------------------------------------------------------------


def test_keyed_hash_is_hmac_sha256_of_the_versioned_canonical_json() -> None:
    key = bytes(range(32))
    text = f"{FINGERPRINT_VERSION}\n{canonical_json(REQUEST)}".encode()
    assert fingerprint(REQUEST, key) == hmac.new(key, text, hashlib.sha256).hexdigest()
    assert fingerprint(REQUEST) == hashlib.sha256(text).hexdigest()


def test_known_keyed_value_never_changes_by_accident() -> None:
    # Changing it would orphan every stored approval: only on purpose, with a new label.
    assert fingerprint(REQUEST, b"k" * 32) == (
        hmac.new(
            b"k" * 32,
            b'warden-action-v1\n{"agent_id":"billing","arguments":{"amount":48213},'
            b'"tool":"send_invoice"}',
            hashlib.sha256,
        ).hexdigest()
    )


def test_different_keys_give_different_hashes() -> None:
    assert fingerprint(REQUEST, b"a" * 32) != fingerprint(REQUEST, b"b" * 32)
    assert fingerprint(REQUEST, b"a" * 32) != fingerprint(REQUEST)


def test_guessing_from_the_database_alone_finds_nothing(tmp_path: Path) -> None:
    """The attack from the review: hash every small amount and compare with the stored
    hash. With the plain SHA-256 it found the amount; keyed, nothing matches."""
    log = SQLiteAuditLog(tmp_path / "a.db")
    client = TestClient(create_app(BASIC_POLICY, audit_log=log))
    client.post(
        "/v1/evaluate",
        json={"agent_id": "billing", "tool": "send_invoice", "arguments": {"amount": 4821}},
    )
    stored = log.recent()[0].action_hash
    assert stored is not None
    for amount in range(10_000):
        guess = REQUEST.model_copy(update={"arguments": {"amount": amount}})
        assert fingerprint(guess) != stored


def test_each_app_without_a_database_gets_its_own_random_key() -> None:
    one = create_app(BASIC_POLICY).state.warden.hash_key
    two = create_app(BASIC_POLICY).state.warden.hash_key
    assert len(one) == 32 and one != two


def test_key_is_never_shown_in_the_repr() -> None:
    w = create_app(BASIC_POLICY, hash_key=b"s" * 32).state.warden
    assert "sss" not in repr(w)


# --- The key file --------------------------------------------------------------------


def test_key_file_lives_next_to_the_database() -> None:
    assert key_path_for(Path("/x/warden-audit.db")) == Path("/x/warden-audit.db.hash-key")


@POSIX
def test_key_file_is_created_private_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "db.hash-key"
    key = load_or_create(path)
    assert len(key) == 32
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == key.hex() + "\n"
    assert load_or_create(path) == key


def test_persistent_approvals_keep_their_key_across_a_restart(tmp_path: Path) -> None:
    def app() -> Any:
        store = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"))
        return create_app(
            BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), approvals=store
        )

    first = app().state.warden.hash_key
    assert app().state.warden.hash_key == first
    assert (tmp_path / "a.db.hash-key").read_text().strip() == first.hex()


@POSIX
def test_key_file_readable_by_others_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "k"
    load_or_create(path)
    path.chmod(0o644)
    with pytest.raises(HashKeyError, match="other users") as info:
        load_or_create(path)
    assert path.read_text().strip() not in str(info.value)


@POSIX
def test_key_file_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real"
    load_or_create(target)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(HashKeyError, match="symlink"):
        load_or_create(link)


@pytest.mark.parametrize("content", ["", "abc", "g" * 64, "a" * 63, "A" * 64, "a" * 66, "é"])
def test_damaged_key_file_is_refused_never_replaced(tmp_path: Path, content: str) -> None:
    path = tmp_path / "k"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(HashKeyError, match="damaged|can't read"):
        load_or_create(path)
    assert path.read_text(encoding="utf-8") == content  # left alone for a restore


def test_key_file_that_is_a_folder_is_refused(tmp_path: Path) -> None:
    (tmp_path / "k").mkdir(mode=0o700)
    with pytest.raises(HashKeyError, match="can't read"):
        load_or_create(tmp_path / "k")


def test_key_file_in_a_missing_folder_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HashKeyError, match="can't create"):
        load_or_create(tmp_path / "missing" / "k")


def test_damaged_key_file_stops_create_app(tmp_path: Path) -> None:
    (tmp_path / "a.db.hash-key").write_text("nope")
    (tmp_path / "a.db.hash-key").chmod(0o600)
    store = ApprovalStore(db=ApprovalDB(tmp_path / "a.db"))
    with pytest.raises(StartupError, match="damaged .expected 64 hex characters"):
        create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), approvals=store)


# --- serve ---------------------------------------------------------------------------


def test_serve_creates_the_key_and_hashes_with_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apps: list[Any] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: apps.append(app))
    db = tmp_path / "audit.db"
    warden.api.main(Settings(policy=BASIC_POLICY, audit_db=db, admin_key="k" * 32))
    key = bytes.fromhex((tmp_path / "audit.db.hash-key").read_text())
    assert apps[0].state.warden.hash_key == key
    TestClient(apps[0]).post(
        "/v1/evaluate", json={"agent_id": "a", "tool": "read_file", "arguments": {"path": "x"}}
    )
    with sqlite3.connect(db) as conn:
        [(stored,)] = conn.execute("SELECT action_hash FROM decisions WHERE tool = 'read_file'")
    real = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "read_file", "arguments": {"path": "x"}}
    )
    assert stored == fingerprint(real, key) != fingerprint(real)


def test_serve_refuses_a_damaged_key_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    (tmp_path / "audit.db.hash-key").write_text("x")
    (tmp_path / "audit.db.hash-key").chmod(0o600)
    with pytest.raises(StartupError, match="damaged"):
        warden.api.main(
            Settings(policy=BASIC_POLICY, audit_db=tmp_path / "audit.db", admin_key="k" * 32)
        )
