"""Data shapes for Warden: what a request looks like and what a decision looks like.

Every model here is strict:
- unknown fields are rejected (extra="forbid"),
- types are not silently converted (strict=True), e.g. 123 is not accepted as "123",
- objects can't be changed after creation (frozen=True).
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

# Lowercase letters, digits, "_", "." and "-", 1 to 64 characters.
# Strict on purpose: "Delete_File", "delete_file " or lookalike Unicode letters
# must never sneak past a rule written for "delete_file".
TOOL_NAME_PATTERN = r"^[a-z0-9_.\-]{1,64}$"
AGENT_ID_PATTERN = r"^[A-Za-z0-9_.\-]{1,128}$"

MAX_ARGUMENTS = 50


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


class EvaluationResult(BaseModel):
    """Warden's answer to an ActionRequest."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    decision: Decision
    reason: str
    # The id of the rule that decided, or None when no rule matched (default deny).
    matched_rule: str | None = None
