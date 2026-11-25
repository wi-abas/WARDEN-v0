"""The approval list shows the human what the action really is: no hidden characters."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import BASIC_POLICY
from hypothesis import given, settings
from hypothesis import strategies as st

from warden.api import _display_safe, create_app
from warden.audit import SQLiteAuditLog
from warden.fingerprint import fingerprint
from warden.models import ActionRequest

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


# --- Characters above U+FFFF (they need 8 hex digits) ---------------------------------


def test_astral_characters_use_a_fixed_length_escape(tmp_path: Path) -> None:
    item = pending(tmp_path, {"to": "boss@company.com", "note": "a\U0001d400b\U000e0100c"})
    assert item["arguments"] == {
        "to": "boss@company.com",
        "note": "a\\U0001d400b\\U000e0100c",
    }


def test_astral_key_cant_hide_another_argument(tmp_path: Path) -> None:
    # Before the fix both names displayed as "ᵀ0" and one value vanished.
    keys = {"\U0001d400": "WIRE $9999", "ᵀ0": "harmless"}
    item = pending(tmp_path, {**keys, "nested": [dict(keys)]})
    expected = {"\\U0001d400": "WIRE $9999", "\\u1d400": "harmless"}
    assert item["arguments"] == {**expected, "nested": [expected]}


def test_escape_looking_text_with_capital_u_is_escaped(tmp_path: Path) -> None:
    item = pending(tmp_path, {"\\U0001d400": "harmless", "\U0001d400": "WIRE $9999"})
    assert item["arguments"] == {"\\u005cU0001d400": "harmless", "\\U0001d400": "WIRE $9999"}


_TRICKY = st.lists(
    st.sampled_from([*"\\uU01dD4ef", "0001d400", "ᵀ", "\U0001d400", "​", "\U000e0100"]),
    max_size=12,
).map("".join)


@settings(max_examples=500)
@given(_TRICKY)
def test_display_can_be_decoded_back(text: str) -> None:
    """One-to-one: undoing the escapes gives the exact original text."""
    shown = _display_safe(text, [])
    assert isinstance(shown, str)
    decoded = re.sub(
        r"\\u([0-9a-f]{4})|\\U([0-9a-fA-F]{8})",
        lambda m: chr(int(m[1] or m[2], 16)),
        shown,
    )
    assert decoded == text


@given(st.dictionaries(_TRICKY, st.just(0), max_size=6))
def test_tricky_names_never_merge(arguments: dict[str, int]) -> None:
    shown = _display_safe([dict(arguments)], [])
    assert isinstance(shown, list) and isinstance(shown[0], dict)
    assert len(shown[0]) == len(arguments)


# --- Characters that draw as blank space or break the line ----------------------------


@pytest.mark.parametrize(
    "ch",
    [
        " ",  # line separator
        " ",  # paragraph separator
        "⠀",  # braille blank
        " ",  # ogham space mark
        " ",  # no-break space
        "　",  # ideographic space
        "\U0001d159",  # null notehead
        "\U00013441",  # Egyptian full blank
        "\U00013442",  # Egyptian half blank
        "\U00016fe4",  # Khitan filler
        "",  # private use: draws whatever the font likes
        "͸",  # unassigned
    ],
)
def test_blank_characters_are_escaped_with_a_warning(tmp_path: Path, ch: str) -> None:
    arguments: dict[str, object] = {"to": "a@b.com", "note": f"pay{ch}now", f"k{ch}": 1}
    item = pending(tmp_path, arguments)
    escape = f"\\U{ord(ch):08x}" if ord(ch) > 0xFFFF else f"\\u{ord(ch):04x}"
    assert item["arguments"] == {"to": "a@b.com", "note": f"pay{escape}now", f"k{escape}": 1}
    assert item["warnings"] == ["contains hidden or look-alike characters (shown as \\uXXXX)"]
    # Only the display is escaped: the approval is bound to the real action.
    real = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "send_email", "arguments": arguments}
    )
    assert item["action_hash"] == fingerprint(real)


def test_ordinary_spaces_and_braille_are_untouched(tmp_path: Path) -> None:
    arguments: dict[str, object] = {"to": "a@b.com", "note": "a b  c ⠁⠃ ᚁ"}
    item = pending(tmp_path, arguments)
    assert item["arguments"] == arguments and item["warnings"] == []
