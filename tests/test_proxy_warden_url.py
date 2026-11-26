"""`warden proxy` finds Warden: --warden-url, then the config file, then WARDEN_URL,
then the default. WARDEN_URL must still be a local http URL (fail closed otherwise)."""

from pathlib import Path

import pytest

from warden import cli
from warden.client import DEFAULT_URL
from warden.mcp_proxy import ProxyConfig


def recorder(seen: list[ProxyConfig]) -> object:
    def fake_serve(config: ProxyConfig, **_: object) -> int:
        seen.append(config)
        return 0

    return fake_serve


ENV_URL = "http://127.0.0.1:8790"
FILE_URL = "http://127.0.0.1:8791"
FLAG_URL = "http://127.0.0.1:8792"


def run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, file_url: str | None, flag: str | None
) -> ProxyConfig:
    seen: list[ProxyConfig] = []

    def fake_serve(config: ProxyConfig, **_: object) -> int:
        seen.append(config)
        return 0

    monkeypatch.setattr("warden.mcp_proxy.serve_stdio", fake_serve)
    argv = ["proxy"]
    if file_url is not None:
        path = tmp_path / "proxy.json"
        path.write_text(f'{{"warden_url": "{file_url}", "server": {{"command": "x"}}}}')
        argv += ["--config", str(path)]
    if flag is not None:
        argv += ["--warden-url", flag]
    argv += ["--", "server"]
    assert cli.main(argv) == 0
    return seen[0]


def test_env_is_used_without_flag_or_config_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDEN_URL", ENV_URL)
    assert run(tmp_path, monkeypatch, file_url=None, flag=None).warden_url == ENV_URL


def test_env_is_used_with_a_config_file_that_has_no_warden_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDEN_URL", ENV_URL)
    path = tmp_path / "proxy.json"
    path.write_text('{"server": {"command": "x"}}')
    seen: list[ProxyConfig] = []
    monkeypatch.setattr("warden.mcp_proxy.serve_stdio", recorder(seen))
    assert cli.main(["proxy", "--config", str(path)]) == 0
    assert seen[0].warden_url == ENV_URL


def test_config_file_beats_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_URL", ENV_URL)
    assert run(tmp_path, monkeypatch, file_url=FILE_URL, flag=None).warden_url == FILE_URL


def test_config_file_with_the_default_value_still_beats_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDEN_URL", ENV_URL)
    assert run(tmp_path, monkeypatch, file_url=DEFAULT_URL, flag=None).warden_url == DEFAULT_URL


def test_flag_beats_config_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_URL", ENV_URL)
    assert run(tmp_path, monkeypatch, file_url=FILE_URL, flag=FLAG_URL).warden_url == FLAG_URL
    assert run(tmp_path, monkeypatch, file_url=None, flag=FLAG_URL).warden_url == FLAG_URL


@pytest.mark.parametrize("value", [None, ""])
def test_default_without_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("WARDEN_URL", raising=False)
    else:
        monkeypatch.setenv("WARDEN_URL", value)
    assert run(tmp_path, monkeypatch, file_url=None, flag=None).warden_url == DEFAULT_URL


@pytest.mark.parametrize(
    "bad", ["http://evil.net:8000", "https://127.0.0.1:8000", "ftp://127.0.0.1/", "nonsense"]
)
def test_non_local_env_url_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    monkeypatch.setenv("WARDEN_URL", bad)
    called: list[ProxyConfig] = []
    monkeypatch.setattr("warden.mcp_proxy.serve_stdio", recorder(called))
    assert cli.main(["proxy", "--", "server"]) == 2
    assert called == []
    assert "invalid settings" in capsys.readouterr().err
