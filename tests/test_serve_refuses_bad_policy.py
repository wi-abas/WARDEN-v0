"""`warden serve` refuses to start with a broken or empty policy."""

from pathlib import Path

import pytest

import warden.api
from warden.cli import main


@pytest.mark.parametrize(
    "content",
    ["not json", '{"rules": [{"id": "x", "tool": "t", "effect": "maybe"}]}', '{"rules": []}'],
)
def test_refuses_to_start(
    content: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "p.json"
    path.write_text(content)
    monkeypatch.setattr(warden.api, "main", lambda s: pytest.fail("server started"))
    assert main(["serve", "--policy", str(path)]) == 2
    assert "not starting" in capsys.readouterr().err


def test_policy_with_warnings_still_starts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "p.json"  # W005 warning, but valid
    path.write_text(
        '{"rules": [{"id": "r", "tool": "t", "effect": "allow",'
        ' "when": [{"arg": "p", "op": "startswith", "value": "/data"}]}]}'
    )
    started: list[object] = []
    monkeypatch.setattr(warden.api, "main", started.append)
    assert main(["serve", "--policy", str(path)]) == 0
    assert len(started) == 1
