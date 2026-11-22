"""Loads the policy (the rulebook) from a JSON file.

Fail closed: if the file is missing, unreadable, not valid JSON, or contains any
invalid rule or tool spec, load_policy() returns an EMPTY policy. With no rules the engine denies
everything, so a broken policy file can never accidentally allow an action.

The policy file is trusted configuration: whoever can edit it controls every
decision. Protect it with file permissions.
"""

import json
import logging
from pathlib import Path
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from warden.models import TOOL_NAME_PATTERN, Rule, ToolSpec

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path("policies/default.json")
SCHEMA_URL = "https://raw.githubusercontent.com/wi-abas/agent-warden/main/schemas/policy-v1.json"
MAX_RULES = 1000


class Policy(BaseModel):
    """The shape of a policy file: {"tools": { ... }, "rules": [ ... ]}.

    "tools" is optional: argument lists per tool (see ToolSpec).
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        json_schema_extra={"title": "Warden policy"},
    )

    # Optional link to the JSON Schema, so editors autocomplete and check the file.
    # Ignored by Warden itself.
    schema_url: str | None = Field(default=None, alias="$schema", max_length=500)
    tools: dict[Annotated[str, Field(pattern=TOOL_NAME_PATTERN)], ToolSpec] = Field(
        default_factory=dict, max_length=MAX_RULES
    )
    rules: tuple[Rule, ...] = Field(max_length=MAX_RULES)

    @model_validator(mode="after")
    def rule_ids_are_unique(self) -> Self:
        ids = [rule.id for rule in self.rules]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")
        return self


EMPTY_POLICY = Policy(rules=())


class DuplicateKeyError(ValueError):
    """The same key appears twice in one JSON object. JSON parsers silently keep the
    last one, so {"effect": "allow", "effect": "deny"} could hide an override."""


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateKeyError(f"duplicate key '{key}' (one value would silently win)")
        seen[key] = value
    return seen


def parse_policy(raw: str) -> Policy:
    """Validate policy JSON. Raises DuplicateKeyError or pydantic's ValidationError."""
    try:
        json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except json.JSONDecodeError:
        pass  # not valid JSON at all: let pydantic report it with its location
    return Policy.model_validate_json(raw)


def describe_errors(exc: ValidationError) -> list[str]:
    """Where each problem is, e.g. "rules.2.when.0.op: Input should be ...".

    Never echoes the file's contents (include_input=False).
    """
    return [
        f"{'.'.join(str(part) for part in error['loc']) or 'file'}: {error['msg']}"
        for error in exc.errors(include_input=False)
    ]


def load_rules(path: Path = DEFAULT_POLICY_PATH) -> tuple[Rule, ...]:
    """Just the rules of the policy file (empty on any problem)."""
    return load_policy(path).rules


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> Policy:
    """Read and validate the policy file. Returns an empty policy on ANY problem."""
    try:
        raw = path.read_text(encoding="utf-8")
        return parse_policy(raw)
    except DuplicateKeyError as exc:
        logger.error("invalid policy file %s, denying everything: %s", path, exc)
    except ValidationError as exc:
        problems = "; ".join(describe_errors(exc))
        logger.error("invalid policy file %s, denying everything: %s", path, problems)
    except Exception as exc:
        logger.error(
            "could not read policy file %s, denying everything: %s", path, type(exc).__name__
        )
    return EMPTY_POLICY
