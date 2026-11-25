"""`warden proxy`: a server that can't start, or stops, ends with a clear message and exit
code, never a traceback or an interpreter abort."""

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from warden.mcp_proxy import ProxyConfig, own_stdin, serve_stdio


def run_proxy(tmp_path: Path, server: dict[str, Any]) -> tuple[int, bytes, str]:
    """A real `warden proxy` process whose client stays connected (stdin open)."""
    config = tmp_path / "proxy.json"
    config.write_text(json.dumps({"server": server}))
    process = subprocess.Popen(  # noqa: S603 (our own command)
        [
            sys.executable,
            "-c",
            "import sys; from warden.cli import main; sys.exit(main(sys.argv[1:]))",
            "proxy",
            "--config",
            str(config),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin and process.stdout and process.stderr
    try:
        code = process.wait(20)
        return code, process.stdout.read(), process.stderr.read().decode()
    finally:
        process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


@pytest.mark.parametrize(
    "server",
    [
        {"command": "warden-no-such-command"},
        {"command": "/"},  # a folder
        {"command": "c\u0000at"},
        {"command": sys.executable, "args": ["a\u0000b"]},
        {"command": sys.executable, "env": {"A=B": "s3cret"}},
        {"command": sys.executable, "env": {"A": "s3cret\u0000"}},
        {"command": sys.executable, "args": ["s3cret" * 1_000_000]},  # too long for the OS
    ],
)
def test_server_that_cant_start_is_a_clear_error(tmp_path: Path, server: dict[str, Any]) -> None:
    code, out, err = run_proxy(tmp_path, server)
    assert code == 2 and out == b""
    assert "warden proxy: can't start the MCP server" in err
    assert "Traceback" not in err and "Fatal" not in err and "s3cret" not in err


def test_server_exit_while_the_client_stays_connected(tmp_path: Path) -> None:
    """The stdin thread is still blocked reading: exiting must not abort the interpreter."""
    code, _, err = run_proxy(
        tmp_path, {"command": sys.executable, "args": ["-c", "raise SystemExit(3)"]}
    )
    assert code == 3 and "Fatal" not in err


def test_serve_stdio_reports_a_server_that_cant_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"")))
    config = ProxyConfig.model_validate(
        {"server": {"command": str(tmp_path / "missing"), "env": {"K": "s3cret"}}}
    )
    assert serve_stdio(config) == 2
    err = capsys.readouterr().err
    assert "can't start the MCP server" in err and "FileNotFoundError" in err
    assert "s3cret" not in err


def test_own_stdin_is_a_separate_reader_on_the_same_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "in"
    path.write_bytes(b"line\n")
    with path.open() as real:
        monkeypatch.setattr(sys, "stdin", real)
        with own_stdin() as stream:
            assert stream is not real.buffer and stream.readline() == b"line\n"
        assert not real.closed and real.fileno() >= 0  # closing ours leaves stdin open
