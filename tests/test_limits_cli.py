"""`warden limits`: show and change rate limits without hand-editing JSON."""

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from warden.cli import main
from warden.limits import DEFAULT_MAX_PENDING_APPROVALS, DEFAULT_REQUESTS_PER_MINUTE
from warden.limits_cli import LimitsEditError, change, show
from warden.policy import load_policy

RULES = [{"id": "ok", "tool": "read_file", "effect": "allow"}]


def write(tmp_path: Path, extra: dict[str, Any] | None = None) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": RULES, **(extra or {})}))
    path.chmod(0o644)
    return path


def limits_of(path: Path) -> Any:
    return json.loads(path.read_text()).get("limits")


def test_defaults_are_1200_and_100() -> None:
    assert (DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_MAX_PENDING_APPROVALS) == (1200, 100)


def test_show_built_in_defaults(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path)
    assert main(["limits", "--policy", str(path)]) == 0
    out = capsys.readouterr().out
    assert "default: 1200 requests/minute, 100 pending approvals  (built-in)" in out


def test_set_defaults_and_one_agent(tmp_path: Path) -> None:
    path = write(tmp_path)
    args = ["limits", "--policy", str(path), "set"]
    assert main([*args, "--requests-per-minute", "2000", "--pending", "200"]) == 0
    assert main([*args, "--agent", "billing", "--requests-per-minute", "30"]) == 0
    assert limits_of(path) == {
        "default": {"requests_per_minute": 2000, "max_pending_approvals": 200},
        "agents": {"billing": {"requests_per_minute": 30}},
    }
    limits = load_policy(path).limits
    assert limits.requests_per_minute("billing") == 30
    assert limits.max_pending_approvals("billing") == 200  # falls back to default
    assert limits.requests_per_minute("other") == 2000
    text = show(path)
    assert "billing: 30 requests/minute, 200 pending approvals" in text
    assert "(built-in)" not in text


def test_set_keeps_the_rest_of_the_policy(tmp_path: Path) -> None:
    path = write(tmp_path, {"tools": {"read_file": {"arguments": ["path"]}}})
    before = json.loads(path.read_text())
    change(path, None, pending=0)
    after = json.loads(path.read_text())
    assert after.pop("limits") == {"default": {"max_pending_approvals": 0}}
    assert after == before


def test_reset_agent_and_defaults(tmp_path: Path) -> None:
    path = write(tmp_path)
    change(path, "a", requests_per_minute=5)
    change(path, None, pending=7)
    assert main(["limits", "--policy", str(path), "reset", "--agent", "a"]) == 0
    assert limits_of(path) == {"default": {"max_pending_approvals": 7}}
    assert main(["limits", "--policy", str(path), "reset"]) == 0
    assert limits_of(path) is None  # back to a policy without a limits section


def test_reset_unknown_agent_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path)
    assert main(["limits", "--policy", str(path), "reset", "--agent", "nobody"]) == 2
    assert "no limits for agent 'nobody'" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flags",
    [
        ["--requests-per-minute", "0"],
        ["--requests-per-minute", "100001"],
        ["--pending", "-1"],
        ["--pending", "1001"],
        ["--agent", "bad agent!", "--pending", "1"],
        [],  # nothing to set
    ],
)
def test_bad_values_change_nothing(
    tmp_path: Path, flags: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    before = path.read_bytes()
    assert main(["limits", "--policy", str(path), "set", *flags]) == 2
    assert path.read_bytes() == before
    assert "warden:" in capsys.readouterr().err
    assert [p.name for p in tmp_path.iterdir()] == ["policy.json"]  # no temp file left


def test_invalid_policy_is_not_touched(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"rules": [{"id": "x", "tool": "t", "effect": "maybe"}]}')
    before = path.read_bytes()
    with pytest.raises(LimitsEditError, match="invalid"):
        change(path, None, pending=1)
    assert path.read_bytes() == before


def test_duplicate_keys_are_not_touched(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"rules": [], "rules": []}')
    with pytest.raises(LimitsEditError, match="invalid"):
        show(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(LimitsEditError, match="can't read"):
        show(tmp_path / "nope.json")


def test_symlink_is_refused(tmp_path: Path) -> None:
    real = write(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(LimitsEditError, match="symlink"):
        change(link, None, pending=1)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_permissions_are_kept(tmp_path: Path) -> None:
    path = write(tmp_path)
    path.chmod(0o600)
    change(path, None, pending=3)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_policy_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, {"limits": {"default": {"requests_per_minute": 9}}})
    monkeypatch.setenv("WARDEN_POLICY", str(path))
    assert main(["limits"]) == 0
    assert "default: 9 requests/minute" in capsys.readouterr().out


@pytest.mark.parametrize("action", [["set", "--requests-per-minute", "7"], ["reset"]])
def test_policy_flag_also_works_after_the_subcommand(tmp_path: Path, action: list[str]) -> None:
    """`warden limits set --policy F` used to fail; only `warden limits --policy F set` worked."""
    path = write(tmp_path, {"limits": {"default": {"requests_per_minute": 9}}})
    assert main(["limits", action[0], "--policy", str(path), *action[1:]]) == 0
    expected = {"default": {"requests_per_minute": 7}} if action[0] == "set" else None
    assert limits_of(path) == expected


def test_policy_flag_after_the_subcommand_wins_over_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path)
    other = tmp_path / "other.json"
    monkeypatch.setenv("WARDEN_POLICY", str(other))
    assert main(["limits", "set", "--policy", str(path), "--pending", "5"]) == 0
    assert limits_of(path) == {"default": {"max_pending_approvals": 5}}
    assert not other.exists()


def agents_file(tmp_path: Path, *ids: str) -> Path:
    from warden.agents import add_agent

    path = tmp_path / "agents.json"
    for agent_id in ids:
        add_agent(path, agent_id)
    return path


def test_set_for_an_agent_missing_from_the_agents_file_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    agents = agents_file(tmp_path, "billing")
    flags = ["--agents", str(agents), "--requests-per-minute", "30"]
    assert main(["limits", "--policy", str(path), "set", "--agent", "biling", *flags]) == 0
    err = capsys.readouterr().err
    assert "warning: agent 'biling' is not in" in err
    assert "have no effect until it is added (warden agent add biling)" in err
    assert limits_of(path) == {"agents": {"biling": {"requests_per_minute": 30}}}  # still set


def test_set_for_a_known_agent_does_not_warn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    agents = agents_file(tmp_path, "billing")
    flags = ["--agents", str(agents), "--requests-per-minute", "30"]
    assert main(["limits", "--policy", str(path), "set", "--agent", "billing", *flags]) == 0
    assert "warning" not in capsys.readouterr().err


def test_agents_file_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    monkeypatch.setenv("WARDEN_AGENTS", str(agents_file(tmp_path, "billing")))
    assert main(["limits", "--policy", str(path), "set", "--agent", "x", "--pending", "1"]) == 0
    assert "warning: agent 'x' is not in" in capsys.readouterr().err


def test_without_an_agents_file_a_new_agent_gets_a_spelling_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)  # no warden-agents.json here
    monkeypatch.delenv("WARDEN_AGENTS", raising=False)
    path = write(tmp_path)
    assert main(["limits", "--policy", str(path), "set", "--agent", "x", "--pending", "1"]) == 0
    assert "warning: no agents file" in capsys.readouterr().err
    # Changing an agent that already has limits: no warning.
    assert main(["limits", "--policy", str(path), "set", "--agent", "x", "--pending", "2"]) == 0
    assert "warning" not in capsys.readouterr().err


def test_unreadable_agents_file_warns_but_changes_the_limits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    bad = tmp_path / "agents.json"
    bad.write_text("{not json")
    flags = ["--agents", str(bad), "--pending", "1"]
    assert main(["limits", "--policy", str(path), "set", "--agent", "x", *flags]) == 0
    assert "warning: can't check agent 'x'" in capsys.readouterr().err
    assert limits_of(path) == {"agents": {"x": {"max_pending_approvals": 1}}}


def test_defaults_never_warn_about_agents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    agents = agents_file(tmp_path, "billing")
    flags = ["--agents", str(agents), "--pending", "3"]
    assert main(["limits", "--policy", str(path), "set", *flags]) == 0
    assert main(["limits", "--policy", str(path), "set", "--pending", "3"]) == 0
    assert "warning" not in capsys.readouterr().err


def test_show_includes_the_rejection_window(tmp_path: Path) -> None:
    assert "rejected actions stay refused for 900 seconds" in show(write(tmp_path))
    extra = {
        "limits": {
            "default": {"rejection_window_seconds": 3600},
            "agents": {"billing": {"rejection_window_seconds": 0}},
        }
    }
    default, billing = show(write(tmp_path, extra)).split("  billing:")
    assert "rejected actions stay refused for 3600 seconds" in default
    assert "rejected actions stay refused for 0 seconds (off)" in billing


def test_reset_keeps_the_rejection_window(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`warden limits` can't set it, so it must not quietly undo it either: that could
    shorten how long a human's "no" lasts."""
    spec = {"requests_per_minute": 5, "rejection_window_seconds": 86400}
    path = write(tmp_path, {"limits": {"default": spec, "agents": {"billing": spec}}})
    kept = {"rejection_window_seconds": 86400}
    args = ["limits", "--policy", str(path), "reset"]
    assert main([*args, "--agent", "billing"]) == 0
    assert "kept rejection_window_seconds" in capsys.readouterr().out
    assert limits_of(path) == {"default": spec, "agents": {"billing": kept}}
    assert main(args) == 0
    assert limits_of(path) == {"default": kept, "agents": {"billing": kept}}
    assert "86400 seconds" in capsys.readouterr().out


def test_reset_without_a_rejection_window_says_nothing_about_it(tmp_path: Path) -> None:
    path = write(tmp_path)
    change(path, None, pending=7)
    assert "kept" not in change(path, None, reset=True)


@pytest.mark.parametrize("raw", [b"\xff{}", b'{"rules": [], "x": ' + b"9" * 5000 + b"}"])
@pytest.mark.parametrize("action", [[], ["set", "--pending", "1"], ["reset"]])
def test_unreadable_policy_text_is_a_clear_error(
    tmp_path: Path, raw: bytes, action: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    assert main(["limits", "--policy", str(path), *action]) == 2
    assert capsys.readouterr().err.startswith("warden: ")
    assert path.read_bytes() == raw


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
@pytest.mark.parametrize("mode", [0o500, 0o000])
def test_folder_without_access_is_a_clear_error(
    tmp_path: Path, mode: int, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    before = path.read_text()
    tmp_path.chmod(mode)
    try:
        assert main(["limits", "--policy", str(path), "set", "--pending", "1"]) == 2
    finally:
        tmp_path.chmod(0o700)
    assert "PermissionError" in capsys.readouterr().err
    assert path.read_text() == before and [p.name for p in tmp_path.iterdir()] == ["policy.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_agents_file_in_a_closed_folder_only_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path)
    closed = tmp_path / "closed"
    closed.mkdir(mode=0o000)
    flags = ["set", "--agent", "a", "--pending", "1", "--agents", str(closed / "a.json")]
    try:
        assert main(["limits", "--policy", str(path), *flags]) == 0
    finally:
        closed.chmod(0o700)
    assert "warning: " in capsys.readouterr().err
