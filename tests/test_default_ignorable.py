"""Every default-ignorable character (drawn as nothing) is treated like a zero-width space."""

import sys
import unicodedata

import pytest
from pydantic import ValidationError

from warden.api import _display_safe
from warden.engine import evaluate
from warden.models import ActionRequest, Condition, Decision, Op, Rule
from warden.unicode_safety import DEFAULT_IGNORABLE_RANGES, is_invisible

# A sample written out by hand, so a typo in the table is caught.
INVISIBLE = [0xAD, 0x34F, 0x61C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x200B, 0x202E, 0x2065]
INVISIBLE += [0x180B, 0x180C, 0x180D, 0x180E, 0x180F, 0x3164, 0xFE00, 0xFE0F, 0xFEFF]
INVISIBLE += [0xFFA0, 0xFFF0, 0xFFF8, 0x1BCA0, 0x1D17A, 0xE0000, 0xE0100, 0xE01EF, 0xE0FFF]

NEIGHBOURS = [0x34E, 0x350, 0x115E, 0x1161, 0x17B3, 0x17B6, 0x180A, 0x1810, 0x3163, 0x3165]
NEIGHBOURS += [0xFE10, 0xFDFF, 0xFFA1, 0x1BCA4, 0xE1000, 0x2764, 0x1F680, ord("a"), ord(" ")]

VALUES: list[tuple[Op, str | list[str], str]] = [
    (Op.EQ, "root", "ro{}ot"),
    (Op.IN, ["root", "admin"], "ro{}ot"),
    (Op.STARTSWITH, "/etc/", "/e{}tc/passwd"),
    (Op.ENDSWITH, "@evil.com", "x@ev{}il.com"),
    (Op.CONTAINS, "rm -rf", "rm -{}rf /"),
    (Op.HOST_IN, ["evil.com"], "https://ev{}il.com/"),
]


def decide(op: Op, value: str | list[str], text: str) -> Decision:
    rules = [
        Rule(id="all", tool="t", effect=Decision.ALLOW),
        Rule(
            id="block",
            tool="t",
            effect=Decision.DENY,
            when=(Condition.model_validate({"arg": "x", "op": op, "value": value}),),
        ),
    ]
    return evaluate(ActionRequest(agent_id="a", tool="t", arguments={"x": text}), rules).decision


@pytest.mark.parametrize("code", INVISIBLE, ids=hex)
@pytest.mark.parametrize(("op", "value", "shape"), VALUES)
def test_cant_dodge_a_deny_rule(op: Op, value: str | list[str], shape: str, code: int) -> None:
    assert decide(op, value, shape.format(chr(code))) is Decision.DENY


@pytest.mark.parametrize("code", INVISIBLE, ids=hex)
def test_policy_value_is_a_load_error(code: int) -> None:
    with pytest.raises(ValidationError, match="invisible or control character"):
        Condition(arg="x", op=Op.EQ, value=f"ro{chr(code)}ot")


@pytest.mark.parametrize("code", INVISIBLE, ids=hex)
def test_approver_sees_it_and_is_warned(code: int) -> None:
    warnings: list[str] = []
    shown = _display_safe({"x": f"a{chr(code)}b"}, warnings)
    assert isinstance(shown, dict)
    assert chr(code) not in str(shown["x"])
    assert warnings


@pytest.mark.parametrize("code", NEIGHBOURS, ids=hex)
def test_ordinary_neighbours_are_not_invisible(code: int) -> None:
    assert not is_invisible(chr(code))


def test_every_format_and_control_character_is_still_invisible() -> None:
    for code in range(sys.maxunicode + 1):
        if unicodedata.category(chr(code)) in {"Cf", "Cc"}:
            assert is_invisible(chr(code))


def test_table_is_sorted_and_has_the_size_unicode_gives() -> None:
    flat = [edge for pair in DEFAULT_IGNORABLE_RANGES for edge in pair]
    assert flat == sorted(flat)
    # The total that DerivedCoreProperties.txt gives for the property.
    assert sum(last - first + 1 for first, last in DEFAULT_IGNORABLE_RANGES) == 4174


def test_emoji_with_a_variation_selector_is_refused_only_where_a_rule_compares() -> None:
    assert decide(Op.CONTAINS, "secret", "nice \U0001f680") is Decision.ALLOW
    assert decide(Op.CONTAINS, "secret", "nice ❤️") is Decision.DENY
    request = ActionRequest(agent_id="a", tool="t", arguments={"body": "❤️"})
    rules = [Rule(id="all", tool="t", effect=Decision.ALLOW)]
    assert evaluate(request, rules).decision is Decision.ALLOW
