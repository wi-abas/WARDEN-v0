"""Data shapes for Warden: what a request looks like and what a decision looks like.

Every model here is strict:
- unknown fields are rejected (extra="forbid"),
- types are not silently converted (strict=True), e.g. 123 is not accepted as "123",
- objects can't be changed after creation (frozen=True).
"""

from enum import StrEnum
from math import isfinite
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

# Lowercase letters, digits, "_", "." and "-", 1 to 64 characters.
# Strict on purpose: "Delete_File", "delete_file " or lookalike Unicode letters
# must never sneak past a rule written for "delete_file".
TOOL_NAME_PATTERN = r"^[a-z0-9_.\-]{1,64}$"
AGENT_ID_PATTERN = r"^[A-Za-z0-9_.\-]{1,128}$"
RULE_ID_PATTERN = r"^[a-z0-9_.\-]{1,64}$"
ARG_NAME_PATTERN = r"^[A-Za-z0-9_.\-]{1,64}$"
APPROVAL_ID_PATTERN = r"^[A-Za-z0-9_\-]{16,64}$"

MAX_ARGUMENTS = 50
MAX_CONDITIONS = 20
MAX_IN_VALUES = 100


class Decision(StrEnum):
    """The three possible answers Warden can give."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionRequest(BaseModel):
    """What an agent wants to do. Treated as untrusted input."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    # Self-declared by the caller, so it is NOT used for security decisions yet.
    agent_id: str = Field(pattern=AGENT_ID_PATTERN)
    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    # Any JSON values. May contain secrets, so never log this field.
    arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=MAX_ARGUMENTS)
    # Sent on the retry after a human approved. NOT part of the action fingerprint.
    approval_id: str | None = Field(default=None, pattern=APPROVAL_ID_PATTERN)


class Op(StrEnum):
    """The fixed set of checks a condition can do. No regex, no code."""

    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    STARTSWITH = "startswith"
    EXISTS = "exists"  # the argument is present (takes no value)
    MISSING = "missing"  # the argument is absent (takes no value)


NUMBER_OPS = {Op.GT, Op.GTE, Op.LT, Op.LTE}
PRESENCE_OPS = {Op.EXISTS, Op.MISSING}


def is_number(value: object) -> bool:
    """True for real numbers. bool is excluded: in Python, True == 1."""
    if isinstance(value, bool):
        return False
    # isfinite() rejects NaN / infinity. Huge ints are fine and skip it (it would overflow).
    return isinstance(value, int) or (isinstance(value, float) and isfinite(value))


def is_scalar(value: object) -> bool:
    return isinstance(value, str | bool) or is_number(value)


class Condition(BaseModel):
    """One check on one argument, e.g. {"arg": "amount", "op": "gt", "value": 500}."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    arg: str = Field(pattern=ARG_NAME_PATTERN)
    op: Op
    value: JsonValue = None  # required for every op except exists / missing

    @model_validator(mode="after")
    def value_fits_op(self) -> "Condition":
        # Catch policy mistakes at load time, e.g. "gt" with a text value.
        if self.op in PRESENCE_OPS and self.value is not None:
            raise ValueError(f"'{self.op}' takes no value")
        if self.op in NUMBER_OPS and not is_number(self.value):
            raise ValueError(f"'{self.op}' needs a number value")
        if self.op is Op.STARTSWITH and not (isinstance(self.value, str) and self.value):
            raise ValueError("'startswith' needs a non-empty text value")
        if self.op is Op.IN:
            ok = isinstance(self.value, list) and 1 <= len(self.value) <= MAX_IN_VALUES
            if not ok or not all(is_scalar(v) for v in self.value):
                raise ValueError(f"'in' needs a list of 1 to {MAX_IN_VALUES} text/number values")
        if self.op in {Op.EQ, Op.NEQ} and not is_scalar(self.value):
            raise ValueError(f"'{self.op}' needs a text, number or true/false value")
        return self


class Rule(BaseModel):
    """One policy rule: when an agent asks for `tool` (and every `when` condition
    holds), the answer is `effect`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(pattern=RULE_ID_PATTERN)
    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    effect: Decision
    when: tuple[Condition, ...] = Field(default=(), max_length=MAX_CONDITIONS)


class ToolSpec(BaseModel):
    """Which arguments a tool may receive. Anything else is denied.

    Closes the "new argument nobody checks" gap: with a spec, an agent can't slip
    in e.g. "bcc" that no rule looks at.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    arguments: tuple[Annotated[str, Field(pattern=ARG_NAME_PATTERN)], ...] = Field(
        max_length=MAX_ARGUMENTS
    )
    required: tuple[Annotated[str, Field(pattern=ARG_NAME_PATTERN)], ...] = ()

    @model_validator(mode="after")
    def names_make_sense(self) -> "ToolSpec":
        if len(set(self.arguments)) != len(self.arguments):
            raise ValueError("'arguments' lists a name twice")
        unknown = sorted(set(self.required) - set(self.arguments))
        if unknown:
            raise ValueError(f"'required' names not in 'arguments': {', '.join(unknown)}")
        return self


class EvaluationResult(BaseModel):
    """Warden's answer to an ActionRequest."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    decision: Decision
    reason: str
    # The id of the rule that decided, or None when no rule matched (default deny).
    matched_rule: str | None = None
    # SHA-256 fingerprint of the exact action (see fingerprint.py), or None on errors.
    action_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    # Set on require_approval (the pending approval to ask a human about) and on an
    # allow that was granted by an approval.
    approval_id: str | None = Field(default=None, pattern=APPROVAL_ID_PATTERN)
