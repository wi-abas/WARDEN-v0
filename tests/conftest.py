import pytest

from warden import audit


@pytest.fixture(autouse=True)
def _audit_db_in_tmp(tmp_path, monkeypatch):
    """Keep every test's audit database in a temp folder, never in the repo."""
    monkeypatch.setattr(audit, "DEFAULT_AUDIT_PATH", tmp_path / "audit.db")
