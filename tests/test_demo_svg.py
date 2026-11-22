"""Smoke test: the README demo image can be regenerated."""

import importlib.util
from pathlib import Path

import pytest

import warden.api


def test_demo_svg_renders() -> None:
    path = Path(__file__).parent.parent / "scripts" / "demo_svg.py"
    spec = importlib.util.spec_from_file_location("demo_svg", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    svg = module.render(module.demo_output())
    assert svg.startswith("<svg") and "REQUIRE_APPROVAL" in svg
    assert "\033" not in svg  # no raw terminal codes left


@pytest.fixture(autouse=True)
def restore_default_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # conftest allows "testserver"; examples must work with the real defaults.
    monkeypatch.setattr(warden.api, "ALLOWED_HOSTS", ("127.0.0.1", "localhost", "::1"))
