"""The demo must keep working: it doubles as an end-to-end test."""

import importlib.util
from pathlib import Path

import pytest

import warden.api
from warden.check import check_policy

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_demo_runs_and_every_step_behaves(capsys: pytest.CaptureFixture[str]) -> None:
    spec = importlib.util.spec_from_file_location("demo", EXAMPLES / "demo.py")
    assert spec is not None and spec.loader is not None
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert demo.run() is True
    out = capsys.readouterr().out
    assert "UNEXPECTED" not in out
    assert "All steps behaved as expected." in out


def test_demo_policy_passes_warden_check() -> None:
    report = check_policy(EXAMPLES / "demo-policy.json")
    assert report.errors == [] and report.warnings == []


@pytest.fixture(autouse=True)
def restore_default_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # conftest allows "testserver"; examples must work with the real defaults.
    monkeypatch.setattr(warden.api, "ALLOWED_HOSTS", ("127.0.0.1", "localhost", "::1"))
