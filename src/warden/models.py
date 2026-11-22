"""Data shapes for Warden: what a request looks like and what a decision looks like.

Every model here is strict:
- unknown fields are rejected (extra="forbid"),
- types are not silently converted (strict=True), e.g. 123 is not accepted as "123",
- objects can't be changed after creation (frozen=True).
"""

import re
import unicodedata
from enum import StrEnum
from math import isfinite
from typing import Annotated, TypeGuard

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

# Lowercase letters, digits, "_", "." and "-", 1 to 64 characters.
# Strict on purpose: "Delete_File", "delete_file " or lookalike Unicode letters
# must never sneak past a rule written for "delete_file".
TOOL_NAME_PATTERN = r"^[a-z0-9_.\-]{1,64}$"
AGENT_ID_PATTERN = r"^[A-Za-z0-9_.\-]{1,128}$"
RULE_ID_PATTERN = r"^[a-z0-9_.\-]{1,64}$"
ARG_NAME_PATTERN = r"^[A-Za-z0-9_.\-]{1,64}$"
# One line of visible text: no control characters (C0, DEL, C1), and no invisible
# formatting characters that can make logs lie (zero-width, bidi overrides like U+202E).
MESSAGE_PATTERN = r"^[^\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]{1,200}$"
APPROVAL_ID_PATTERN = r"^[A-Za-z0-9_\-]{16,64}$"

MAX_ARGUMENTS = 50
MAX_ARG_DEPTH = 8  # "a.b.c..." at most this many levels deep
MAX_CONDITIONS = 20
MAX_IN_VALUES = 100
# A host name as written in a policy: lowercase ASCII (use punycode "xn--..." for
# international names), optionally starting with "." to include subdomains.
HOST_PATTERN = r"^\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"


class Decision(StrEnum):
    """The three possible answers Warden can give."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class _ActionFields(BaseModel):
    """Fields shared by the request on the wire and the action Warden evaluates."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    # Any JSON values. May contain secrets, so never log this field.
    arguments: dict[str, JsonValue] = Field(default_factory=dict, max_length=MAX_ARGUMENTS)
    # Sent on the retry after a human approved. NOT part of the action fingerprint.
    approval_id: str | None = Field(default=None, pattern=APPROVAL_ID_PATTERN)

    @field_validator("arguments")
    @classmethod
    def numbers_are_finite(cls, arguments: dict[str, JsonValue]) -> dict[str, JsonValue]:
        # JSON parsers accept 1e400 (infinity) and NaN, but they have no exact JSON
        # form, so the action can't be fingerprinted. Reject them as bad input.
        stack: list[JsonValue] = [arguments]
        while stack:
            value = stack.pop()
            if isinstance(value, float) and not isfinite(value):
                raise ValueError("numbers must be finite (no infinity or NaN)")
            if isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        return arguments


class ActionRequest(_ActionFields):
    """What an agent wants to do, with WHO is asking settled. Treated as untrusted input.

    With agent tokens (--agents), agent_id comes from the token; without them it is
    self-declared by the caller.
    """

    agent_id: str = Field(pattern=AGENT_ID_PATTERN)


class EvaluateRequest(_ActionFields):
    """The body of POST /v1/evaluate. agent_id may be left out when the request
    carries an agent token (it then comes from the token)."""

    agent_id: str | None = Field(default=None, pattern=AGENT_ID_PATTERN)


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
    ENDSWITH = "endswith"
    EXISTS = "exists"  # the argument is present (takes no value)
    MISSING = "missing"  # the argument is absent (takes no value)
    # The URL's real host is one of these (any scheme/port/case). ".x.com" = x.com
    # and any subdomain of it.
    HOST_IN = "host_in"


NUMBER_OPS = {Op.GT, Op.GTE, Op.LT, Op.LTE}
PRESENCE_OPS = {Op.EXISTS, Op.MISSING}
TEXT_OPS = {Op.EQ, Op.NEQ, Op.IN, Op.STARTSWITH, Op.ENDSWITH}  # may use ignore_case


def is_number(value: object) -> TypeGuard[int | float]:
    """True for real numbers. bool is excluded: in Python, True == 1."""
    if isinstance(value, bool):
        return False
    # isfinite() rejects NaN / infinity. Huge ints are fine and skip it (it would overflow).
    return isinstance(value, int) or (isinstance(value, float) and isfinite(value))


def is_scalar(value: object) -> bool:
    return isinstance(value, str | bool) or is_number(value)


def _check_policy_text(text: str, op: "Op") -> None:
    """Catch policy typos that would make a rule silently never match.

    Requests containing invisible or look-alike characters, or paths/URLs/emails with
    spaces at the edges, are refused, so a rule VALUE containing them could never match
    anything: a deny rule with such a typo would protect nothing, without any warning.
    """
    if any(unicodedata.category(ch) in {"Cf", "Cc"} for ch in text):
        raise ValueError("value contains an invisible or control character (typo?)")
    if unicodedata.normalize("NFKC", text) != unicodedata.normalize("NFC", text):
        raise ValueError("value contains a look-alike character such as a full-width letter")
    if text != text.strip():
        shaped = "/" in text or "@" in text
        if op in {Op.EQ, Op.NEQ, Op.IN} or shaped:
            raise ValueError("value starts or ends with a space (typo?)")


ArgName = Annotated[str, Field(pattern=ARG_NAME_PATTERN)]


class Condition(BaseModel):
    """One check on one argument, e.g. {"arg": "amount", "op": "gt", "value": 500}.

    `arg` is a top-level argument name ("to"; a dot is just part of the name, so
    "file.name" means the argument called "file.name"), or a list of keys that points
    inside an object: ["headers", "to"].
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    arg: ArgName | tuple[ArgName, ...]

    @field_validator("arg", mode="before")
    @classmethod
    def list_is_a_path(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("arg")
    @classmethod
    def path_has_a_shape(cls, value: str | tuple[str, ...]) -> str | tuple[str, ...]:
        if isinstance(value, tuple) and not 1 <= len(value) <= MAX_ARG_DEPTH:
            raise ValueError(
                f"'arg' must be a name, or a list of 1 to {MAX_ARG_DEPTH} names like "
                f'["headers", "to"]'
            )
        return value

    @property
    def path(self) -> tuple[str, ...]:
        """The keys to follow from the top-level arguments, e.g. ("headers", "to")."""
        return (self.arg,) if isinstance(self.arg, str) else self.arg

    @property
    def label(self) -> str:
        """How to name this argument in messages (policy text, never request data)."""
        return ".".join(self.path)

    op: Op
    value: JsonValue = None  # required for every op except exists / missing
    # Compare text without caring about upper/lower case, e.g. email domains.
    ignore_case: bool = False

    @model_validator(mode="after")
    def value_fits_op(self) -> "Condition":
        # Catch policy mistakes at load time, e.g. "gt" with a text value.
        if self.op in PRESENCE_OPS and self.value is not None:
            raise ValueError(f"'{self.op}' takes no value")
        if self.op in NUMBER_OPS and not is_number(self.value):
            raise ValueError(f"'{self.op}' needs a number value")
        if self.op in {Op.STARTSWITH, Op.ENDSWITH} and not (
            isinstance(self.value, str) and self.value
        ):
            raise ValueError(f"'{self.op}' needs a non-empty text value")
        if self.ignore_case:
            values = self.value if isinstance(self.value, list) else [self.value]
            if self.op not in TEXT_OPS or not all(isinstance(v, str) for v in values):
                raise ValueError("'ignore_case' only works with text values")
        if self.op is Op.IN:
            ok = (
                isinstance(self.value, list)
                and 1 <= len(self.value) <= MAX_IN_VALUES
                and all(is_scalar(v) for v in self.value)
            )
            if not ok:
                raise ValueError(f"'in' needs a list of 1 to {MAX_IN_VALUES} text/number values")
        if self.op is Op.HOST_IN:
            ok = (
                isinstance(self.value, list)
                and 1 <= len(self.value) <= MAX_IN_VALUES
                and all(isinstance(v, str) and re.fullmatch(HOST_PATTERN, v) for v in self.value)
            )
            if not ok:
                raise ValueError(
                    f"'host_in' needs a list of 1 to {MAX_IN_VALUES} lowercase host names, "
                    'e.g. ["api.example.com", ".example.com"]'
                )
        if self.op in {Op.EQ, Op.NEQ} and not is_scalar(self.value):
            raise ValueError(f"'{self.op}' needs a text, number or true/false value")
        texts = self.value if isinstance(self.value, list) else [self.value]
        for text in texts:
            if isinstance(text, str):
                _check_policy_text(text, self.op)
        return self


class Rule(BaseModel):
    """One policy rule: when an agent asks for `tool` (and every `when` condition
    holds), the answer is `effect`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(pattern=RULE_ID_PATTERN)
    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    effect: Decision
    when: tuple[Condition, ...] = Field(default=(), max_length=MAX_CONDITIONS)
    # Shown as the decision's reason, e.g. "Payments over €500 need finance approval".
    # One line, no control characters (it ends up in logs and the audit log).
    message: str | None = Field(default=None, pattern=MESSAGE_PATTERN)


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
