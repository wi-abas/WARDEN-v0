"""Settings: flags beat environment variables beat defaults; bad values stop startup."""

from pathlib import Path

import pytest

import warden.api
from warden.cli import main
from warden.policy import DEFAULT_POLICY_PATH
from warden.settings import Settings, SettingsError, resolve

KEY = "k" * 32


def test_defaults() -> None:
    assert resolve(env={}) == Settings()


def test_environment_variables(tmp_path: Path) -> None:
    env = {
        "WARDEN_POLICY": str(DEFAULT_POLICY_PATH),
        "WARDEN_PORT": "9000",
        "WARDEN_AUDIT_DB": str(tmp_path / "a.db"),
        "WARDEN_RETENTION_DAYS": "365",
        "WARDEN_ADMIN_KEY": KEY,
    }
    s = resolve(env=env)
    assert (s.port, s.audit_db, s.retention_days, s.admin_key) == (
        9000,
        tmp_path / "a.db",
        365,
        KEY,
    )


def test_flags_beat_environment() -> None:
    assert resolve(port="9001", env={"WARDEN_PORT": "9000"}).port == 9001


def test_zero_retention_means_forever() -> None:
    assert resolve(retention_days="0", env={}).retention_days is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"port": "0"}, "between 1 and 65535"),
        ({"port": "70000"}, "between 1 and 65535"),
        ({"port": "abc"}, "whole number"),
        ({"port": "-1"}, "whole number"),
        ({"retention_days": "-5"}, "whole number"),
        ({"retention_days": "1.5"}, "whole number"),
        ({"policy": "does-not-exist.json"}, "policy file not found"),
        ({"audit_db": "no/such/folder/a.db"}, "folder does not exist"),
    ],
)
def test_bad_values_stop_startup(kwargs: dict, message: str) -> None:
    with pytest.raises(SettingsError, match=message):
        resolve(**kwargs, env={})


def test_bad_environment_value_names_the_variable() -> None:
    with pytest.raises(SettingsError, match="WARDEN_PORT"):
        resolve(env={"WARDEN_PORT": "nope"})


def test_bad_flag_names_the_flag() -> None:
    with pytest.raises(SettingsError, match="--retention-days"):
        resolve(retention_days="x", env={})


@pytest.mark.parametrize("key", ["short", "k" * 31, " " + "k" * 32, "k" * 16 + " " + "k" * 16])
def test_weak_or_odd_admin_keys_are_refused(key: str) -> None:
    with pytest.raises(SettingsError, match="WARDEN_ADMIN_KEY"):
        resolve(env={"WARDEN_ADMIN_KEY": key})


def test_admin_key_never_appears_in_errors_or_repr() -> None:
    canary = "sk-live-FAKE-123"  # fake secret used to detect leaks
    with pytest.raises(SettingsError) as exc:
        resolve(env={"WARDEN_ADMIN_KEY": canary})
    assert canary not in str(exc.value)
    assert KEY not in repr(resolve(env={"WARDEN_ADMIN_KEY": KEY}))


def test_admin_key_has_no_flag() -> None:
    with pytest.raises(SystemExit):
        main(["serve", "--admin-key", KEY])


# --- CLI wiring ------------------------------------------------------------------------


def test_cli_passes_settings_to_the_server(monkeypatch, tmp_path: Path) -> None:
    started: list[Settings] = []
    monkeypatch.setattr(warden.api, "main", started.append)
    monkeypatch.setenv("WARDEN_ADMIN_KEY", KEY)
    code = main(["serve", "--port", "9123", "--audit-db", str(tmp_path / "x.db")])
    assert code == 0
    assert started[0].port == 9123
    assert started[0].audit_db == tmp_path / "x.db"
    assert started[0].admin_key == KEY


def test_no_subcommand_means_serve(monkeypatch) -> None:
    started: list[Settings] = []
    monkeypatch.setattr(warden.api, "main", started.append)
    assert main([]) == 0
    assert started == [resolve(env={})]


def test_cli_bad_setting_exits_2_without_starting(monkeypatch, capsys) -> None:
    monkeypatch.setattr(warden.api, "main", lambda s: pytest.fail("server started"))
    assert main(["serve", "--port", "99999"]) == 2
    assert "between 1 and 65535" in capsys.readouterr().err
