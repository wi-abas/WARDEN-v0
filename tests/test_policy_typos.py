"""Rule values with typos that would silently never match are load errors."""

import json

import pytest
from pydantic import ValidationError

from warden.models import Rule


def rule(op: str, value: object) -> Rule:
    return Rule.model_validate_json(
        json.dumps(
            {
                "id": "r",
                "tool": "t",
                "effect": "deny",
                "when": [{"arg": "a", "op": op, "value": value}],
            }
        )
    )


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("endswith", "@evil.com "),
        ("endswith", " @evil.com"),
        ("endswith", "@evil.com​"),
        ("startswith", "/etc/­"),
        ("startswith", "/ｅtc/"),
        ("startswith", "https://evil.net/ "),
        ("eq", "root "),
        ("eq", "ro‮ot"),
        ("in", ["ok", "bad\t"]),
        ("neq", " x"),
    ],
)
def test_typo_values_are_rejected(op: str, value: object) -> None:
    with pytest.raises(ValidationError):
        rule(op, value)


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("startswith", "Re: "),  # a subject prefix may end with a space
        ("endswith", " (draft)"),
        ("eq", "Grüße"),
        ("in", ["日本", "Zürich"]),
        ("eq", 5),
        ("startswith", "/data/"),
    ],
)
def test_legitimate_values_still_load(op: str, value: object) -> None:
    rule(op, value)
