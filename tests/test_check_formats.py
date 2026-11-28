"""`warden check --format json|github`: the same report for scripts and GitHub Actions."""

import json
from pathlib import Path

import pytest

from warden.check import Report, _split_code, check_policy, format_github, format_json
from warden.cli import main

NO_MINIMUM = {
    "rules": [
        {"id": "a", "tool": "t", "effect": "allow", "when": [{"arg": "n", "op": "lte", "value": 5}]}
    ]
}


def write(tmp_path: Path, policy: object, name: str = "policy.json") -> Path:
    path = tmp_path / name
    path.write_text(policy if isinstance(policy, str) else json.dumps(policy), encoding="utf-8")
    return path


def test_json_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, NO_MINIMUM)
    assert main(["check", str(path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["file"] == str(path)
    assert data["valid"] is True
    assert (data["rules"], data["tools"], data["errors"], data["notes"]) == (1, 1, [], [])
    [warning] = data["warnings"]
    assert warning["code"] == "W021"
    assert warning["message"].startswith('rule "a" allows "n" lte 5 with no minimum')


def test_json_strict_and_invalid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(write(tmp_path, NO_MINIMUM)), "--format", "json", "--strict"]) == 1
    capsys.readouterr()
    assert main(["check", str(write(tmp_path, "not json")), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] is False and data["errors"] and data["warnings"] == []


def test_json_keeps_non_ascii_readable(tmp_path: Path) -> None:
    report = Report(errors=["règle"])
    assert '"règle"' in format_json(tmp_path / "p.json", report)


def test_github_annotations(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write(tmp_path, NO_MINIMUM)
    assert main(["check", str(path), "--format", "github"]) == 0
    out = capsys.readouterr().out.splitlines()
    file = str(path).replace(":", "%3A").replace(",", "%2C")
    assert out[0].startswith(f"::warning file={file},title=warden check W021::rule ")
    assert any(line.startswith("✓ ") for line in out)  # the readable report follows
    assert out[-1] == "0 errors, 1 warning."


def test_github_errors_and_escaping() -> None:
    report = Report(errors=["bad 100%\nline two\rx"], warnings=["no code here, 50%"])
    out = format_github(Path("a,b:c.json"), report).splitlines()
    assert out[0] == "::error file=a%2Cb%3Ac.json,title=warden check::bad 100%25%0Aline two%0Dx"
    assert out[1] == "::warning file=a%2Cb%3Ac.json,title=warden check::no code here, 50%25"


def test_github_title_escapes_too() -> None:
    out = format_github(Path("p.json"), Report(warnings=["W001: a, b"])).splitlines()
    assert out[0] == "::warning file=p.json,title=warden check W001::a, b"


@pytest.mark.parametrize(
    ("warning", "split"),
    [
        ("W021: rule x", ("W021", "rule x")),
        ("W21: rule x", (None, "W21: rule x")),
        ("W0213: x", (None, "W0213: x")),
        ("note W021: x", (None, "note W021: x")),
        ("W021:x", (None, "W021:x")),
    ],
)
def test_split_code(warning: str, split: tuple[str | None, str]) -> None:
    assert _split_code(warning) == split


def test_every_warning_has_a_code(tmp_path: Path) -> None:
    # A policy that triggers several warnings: each one starts with its code.
    policy = {
        "rules": [
            {"id": "a", "tool": "t", "effect": "allow"},
            {"id": "b", "tool": "t", "effect": "allow"},
            {
                "id": "c",
                "tool": "u",
                "effect": "deny",
                "when": [{"arg": "x", "op": "eq", "value": 1}],
            },
        ]
    }
    report = check_policy(write(tmp_path, policy))
    assert report.warnings
    assert all(_split_code(w)[0] for w in report.warnings)
