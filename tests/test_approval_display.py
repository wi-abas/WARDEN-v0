"""The approval list shows the human what the action really is: no hidden characters."""

from pathlib import Path

from fastapi.testclient import TestClient
from helpers import BASIC_POLICY
from hypothesis import given
from hypothesis import strategies as st

from warden.api import _display_safe, create_app
from warden.audit import SQLiteAuditLog

KEY = "k" * 32
ADMIN = {"X-Warden-Admin-Key": KEY}


def pending(tmp_path: Path, arguments: dict[str, object]) -> dict[str, object]:
    client = TestClient(
        create_app(BASIC_POLICY, audit_log=SQLiteAuditLog(tmp_path / "a.db"), admin_key=KEY)
    )
    client.post(
        "/v1/evaluate", json={"agent_id": "a", "tool": "send_email", "arguments": arguments}
    )
    response = client.get("/v1/approvals", headers=ADMIN)
    for ch in ["‮", "​", "­", "ｅ"]:
        assert ch not in response.text  # never sent raw to the approver
    [item] = response.json()
    assert isinstance(item, dict)
    return item


def test_direction_override_is_shown_escaped(tmp_path: Path) -> None:
    item = pending(tmp_path, {"to": "boss@company.com", "note": "pay ‮moc.live@kcab"})
    assert item["arguments"] == {"to": "boss@company.com", "note": "pay \\u202emoc.live@kcab"}
    assert item["warnings"] == ["contains hidden or look-alike characters (shown as \\uXXXX)"]


def test_invisible_and_lookalike_characters_in_values_and_keys(tmp_path: Path) -> None:
    item = pending(
        tmp_path,
        {"to​": "x@ｅvil.com", "list": ["a­b", {"k": "c\u0000d"}]},
    )
    assert item["arguments"] == {
        "to\\u200b": "x@\\uff45vil.com",
        "list": ["a\\u00adb", {"k": "c\\u0000d"}],
    }
    assert item["warnings"]


def test_normal_text_is_untouched(tmp_path: Path) -> None:
    arguments = {"to": "zoë@example.com", "body": "Grüße aus München 🚀 日本語", "n": 5}
    item = pending(tmp_path, arguments)
    assert item["arguments"] == arguments
    assert item["warnings"] == []


def test_escaped_looking_key_cant_hide_another_argument(tmp_path: Path) -> None:
    # Before the fix both keys displayed as "note\u200b" and one value vanished.
    item = pending(tmp_path, {"note\\u200b": "harmless", "note\u200b": "WIRE $9999"})
    shown = item["arguments"]
    assert isinstance(shown, dict)
    assert shown == {"note\\u005cu200b": "harmless", "note\\u200b": "WIRE $9999"}


def test_backslash_without_u_is_untouched(tmp_path: Path) -> None:
    item = pending(tmp_path, {"to": "boss@company.com", "path": "C:\\Users\\bob"})
    assert item["arguments"] == {"to": "boss@company.com", "path": "C:\\Users\\bob"}
    assert item["warnings"] == []


@given(st.dictionaries(st.text(max_size=8), st.just(0), max_size=6))
def test_display_never_merges_two_keys(arguments: dict[str, int]) -> None:
    shown = _display_safe(dict(arguments), [])
    assert isinstance(shown, dict)
    assert len(shown) == len(arguments)
