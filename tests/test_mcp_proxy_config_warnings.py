"""`warden proxy` warns at start about how the server is launched: unpinned packages,
docker images without a digest, secret keys written in the config file, and a config
file another user could replace. Warnings only; never an environment value."""

import json
import os
from pathlib import Path
from typing import Any

import pytest

import warden.mcp_proxy
from warden.cli import main
from warden.mcp_proxy import ProxyConfig, _package_arg, config_warnings


def warnings_for(command: str, *args: str, env: dict[str, str] | None = None) -> list[str]:
    server = {"command": command, "args": list(args), "env": env or {}}
    return config_warnings(ProxyConfig.model_validate({"server": server}, strict=False))


@pytest.mark.parametrize(
    ("command", "args", "package", "example"),
    [
        (
            "npx",
            ["-y", "@modelcontextprotocol/server-filesystem", "/w"],
            "@modelcontextprotocol/server-filesystem",
            "@modelcontextprotocol/server-filesystem@1.2.3",
        ),
        ("npx", ["--yes", "pkg@latest"], "pkg@latest", "pkg@1.2.3"),
        ("npx", ["pkg@^1.2.3"], "pkg@^1.2.3", "pkg@1.2.3"),
        ("/usr/local/bin/npx", ["-p", "pkg", "tool"], "pkg", "pkg@1.2.3"),
        ("npx.cmd", ["pkg"], "pkg", "pkg@1.2.3"),
        ("bunx", ["pkg"], "pkg", "pkg@1.2.3"),
        ("pnpx", ["pkg"], "pkg", "pkg@1.2.3"),
        ("uvx", ["mcp-server-git"], "mcp-server-git", "mcp-server-git==1.2.3"),
        (
            "uvx",
            ["--python", "3.12", "mcp-server-git>=0.6"],
            "mcp-server-git>=0.6",
            "mcp-server-git==1.2.3",
        ),
        (
            "UVX.EXE",
            ["--from", "git+https://x/y", "tool"],
            "git+https://x/y",
            "git+https://x/y@<commit>",
        ),
        ("uv", ["tool", "run", "pkg"], "pkg", "pkg==1.2.3"),
        ("pipx", ["run", "--spec", "pkg", "tool"], "pkg", "pkg==1.2.3"),
    ],
)
def test_unpinned_packages(command: str, args: list[str], package: str, example: str) -> None:
    runner = {
        "/usr/local/bin/npx": "npx",
        "npx.cmd": "npx",
        "UVX.EXE": "uvx",
        "uv": "uv tool run",
        "pipx": "pipx run",
    }.get(command, command)
    assert warnings_for(command, *args) == [
        f"{runner} starts {package!r} without an exact version: each start may download "
        f"whatever was published last. Pin it, e.g. {example}."
    ]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@scope/pkg@1.2.3"]),
        ("npx", ["pkg@v1.2.3-beta.1"]),
        ("uvx", ["mcp-server-git==0.6.2"]),
        ("uvx", ["--with", "extra", "pkg@2.0.0"]),
        ("uvx", ["--from", "git+https://x/y@" + "a" * 40, "tool"]),
        ("pipx", ["run", "pkg==1.0.0"]),
        ("uv", ["run", "server.py"]),
        ("pipx", ["install", "pkg"]),
        ("node", ["server.js"]),
        ("npx", ["-y"]),
        ("uvx", ["--from"]),
        ("docker", ["run", "-i", "--rm", "mcp/fetch@sha256:" + "0" * 64]),
        ("docker", ["pull", "mcp/fetch"]),
    ],
)
def test_pinned_or_other_commands_dont_warn(command: str, args: list[str]) -> None:
    assert warnings_for(command, *args) == []


@pytest.mark.parametrize("program", ["docker", "podman", "/usr/bin/docker"])
def test_docker_without_digest(program: str) -> None:
    name = Path(program).name
    assert warnings_for(program, "run", "-i", "--rm", "mcp/fetch:latest") == [
        f"{name} run without an image digest (image@sha256:...): the tag can be moved to a "
        f"different image."
    ]


@pytest.mark.parametrize(
    "secret",
    [
        "sk-ant-api03-x",
        "ghp_" + "a" * 36,
        "github_pat_x",
        "xoxb-1",
        "AKIA" + "A" * 16,
        "AIza" + "b" * 35,
        "npm_" + "c" * 36,
        "hf_" + "d" * 34,
        "glpat-x",
        "sk_live_x",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
    ],
)
def test_secret_in_server_env(secret: str) -> None:
    found = warnings_for("node", "s.js", env={"API_KEY": secret, "PLAIN": "hello"})
    assert found == [
        "server.env 'API_KEY' looks like a real secret key, written in the config file (easy "
        "to commit or share). Set it in the MCP client's env instead: the server gets the "
        "proxy's environment."
    ]
    assert all(secret not in w for w in found)


@pytest.mark.parametrize("value", ["", "hello", "sk-", "AKIA123", "xyz ghp_abc", "${GITHUB_TOKEN}"])
def test_ordinary_env_values_dont_warn(value: str) -> None:
    assert warnings_for("node", env={"X": value}) == []


def test_package_arg() -> None:
    assert _package_arg(("-y", "a", "b")) == "a"
    assert _package_arg(("--package", "a", "b")) == "a"
    assert _package_arg(("--with", "x", "a")) == "a"
    assert _package_arg(("-y",)) is None
    assert _package_arg(("--spec",)) is None


def run_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config: dict[str, Any]) -> list[str]:
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(path, 0o600)
    calls: list[ProxyConfig] = []

    def fake_serve(config: ProxyConfig, **_: object) -> int:
        calls.append(config)
        return 0

    monkeypatch.setattr(warden.mcp_proxy, "serve_stdio", fake_serve)
    return [str(path)] if main(["proxy", "--no-auth", "--config", str(path)]) == 0 and calls else []


def test_cli_prints_warnings_then_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli(tmp_path, monkeypatch, {"server": {"command": "npx", "args": ["-y", "pkg"]}})
    err = capsys.readouterr().err
    assert "warden proxy: warning: npx starts 'pkg' without an exact version" in err


def test_cli_quiet_for_a_pinned_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli(tmp_path, monkeypatch, {"server": {"command": "npx", "args": ["pkg@1.0.0"]}})
    assert "warning" not in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_cli_warns_about_a_replaceable_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "shared"
    folder.mkdir()
    os.chmod(folder, 0o777)  # noqa: S103 (the risk under test)
    path = folder / "proxy.json"
    path.write_text(json.dumps({"server": {"command": "node"}}), encoding="utf-8")
    monkeypatch.setattr(warden.mcp_proxy, "serve_stdio", lambda config, **_: 0)
    assert main(["proxy", "--no-auth", "--config", str(path)]) == 0
    err = capsys.readouterr().err
    assert f"warden proxy: warning: {path}: another user could replace it (" in err
