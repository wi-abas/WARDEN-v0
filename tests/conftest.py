import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

import warden.api
from warden import audit


@pytest.fixture(autouse=True)
def _audit_db_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test's audit database in a temp folder, never in the repo."""
    monkeypatch.setattr(audit, "DEFAULT_AUDIT_PATH", tmp_path / "audit.db")
    # FastAPI's TestClient sends "Host: testserver".
    monkeypatch.setattr(warden.api, "ALLOWED_HOSTS", (*warden.api.ALLOWED_HOSTS, "testserver"))
    # Write rejection events immediately, so tests can read them right away.
    monkeypatch.setattr(warden.api, "RECORD_REJECTIONS_IN_BACKGROUND", False)


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """Put every logger back as it was after each test.

    api.main() and `warden proxy` configure logging (dictConfig / basicConfig) with
    handlers that write to the test's captured stderr. Left in place, later tests log
    into a closed stream, and every message prints a "Logging error" traceback: the
    proxy flood test (20,000 warnings) went from ~1 s to ~10 s and timed out on CI.
    """
    manager = logging.Logger.manager
    loggers = [logging.getLogger(), *manager.loggerDict.values()]
    saved = {
        logger: (list(logger.handlers), logger.level, logger.propagate, logger.disabled)
        for logger in loggers
        if isinstance(logger, logging.Logger)
    }
    yield
    for logger in [logging.getLogger(), *manager.loggerDict.values()]:
        if not isinstance(logger, logging.Logger):
            continue
        handlers, level, propagate, disabled = saved.get(logger, ([], logging.NOTSET, True, False))
        logger.handlers = handlers
        logger.setLevel(level)
        logger.propagate = propagate
        logger.disabled = disabled
