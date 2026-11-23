"""Loads the policy (the rulebook) from a JSON file.

Fail closed: if the file is missing, unreadable, not valid JSON, or contains any
invalid rule or tool spec, load_policy() returns an EMPTY policy. With no rules the engine denies
everything, so a broken policy file can never accidentally allow an action.

The policy file is trusted configuration: whoever can edit it controls every
decision. Protect it with file permissions.
"""

import json
import logging
import re
from pathlib import Path
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from warden.limits import Limits
from warden.models import RULE_ID_PATTERN, TOOL_NAME_PATTERN, Rule, ToolSpec

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path("policies/default.json")
SCHEMA_URL = "https://raw.githubusercontent.com/wi-abas/agent-warden/main/schemas/policy-v1.json"
MAX_RULES = 1000


class Policy(BaseModel):
    """The shape of a policy file: {"tools": { ... }, "rules": [ ... ], "limits": { ... }}.

    "tools" is optional: argument lists per tool (see ToolSpec).
    "limits" is optional: per-agent rate limits and approval quotas (see Limits).
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
    # Optional per-agent rate limits and approval quotas (see limits.py).
    limits: Limits = Limits()

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
    except (json.JSONDecodeError, RecursionError):
        pass  # not valid JSON, or nested too deeply: let pydantic report it
    return Policy.model_validate_json(raw)


def describe_errors(exc: ValidationError, raw: str | None = None) -> list[str]:
    """Where each problem is, e.g. "rules.2.when.0.op: Input should be ...".

    With the policy text `raw`, a problem inside a rule also names the rule:
    "rule 'pay-small' (rules.2).when.0.op: ...". Only an id that is a VALID rule id is
    shown; otherwise the file's contents are never echoed (include_input=False).
    """
    ids = _rule_ids(raw) if raw is not None else {}
    out = []
    for error in exc.errors(include_input=False):
        loc = [str(part) for part in error["loc"]]
        where = ".".join(loc) or "file"
        if len(loc) >= 2 and loc[0] == "rules" and loc[1] in ids:
            where = ".".join([f"rule '{ids[loc[1]]}' (rules.{loc[1]})", *loc[2:]])
        out.append(f"{where}: {error['msg']}")
    return out


def _rule_ids(raw: str) -> dict[str, str]:
    """Index (as text) -> id, for rules whose id is a valid rule id. Empty on any problem."""
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return {}
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        return {}
    return {
        str(index): rule["id"]
        for index, rule in enumerate(rules)
        if isinstance(rule, dict)
        and isinstance(rule.get("id"), str)
        and re.fullmatch(RULE_ID_PATTERN, rule["id"])
    }


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
        problems = "; ".join(describe_errors(exc, raw))
        logger.error("invalid policy file %s, denying everything: %s", path, problems)
    except Exception as exc:
        logger.error(
            "could not read policy file %s, denying everything: %s", path, type(exc).__name__
        )
    return EMPTY_POLICY
