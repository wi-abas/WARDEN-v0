"""Loads the policy (the rulebook) from a JSON file.

Fail closed: if the file is missing, unreadable, not valid JSON, or contains any
invalid rule, load_rules() returns NO rules. With no rules the engine denies
everything, so a broken policy file can never accidentally allow an action.

The policy file is trusted configuration: whoever can edit it controls every
decision. Protect it with file permissions.
"""

import logging
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from warden.models import Rule

logger = logging.getLogger(__name__)

DEFAULT_POLICY_PATH = Path("policies/default.json")
MAX_RULES = 1000


class Policy(BaseModel):
    """The shape of a policy file: {"rules": [ ... ]}."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    rules: tuple[Rule, ...] = Field(max_length=MAX_RULES)

    @model_validator(mode="after")
    def rule_ids_are_unique(self) -> Self:
        ids = [rule.id for rule in self.rules]
        duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")
        return self


def load_rules(path: Path = DEFAULT_POLICY_PATH) -> tuple[Rule, ...]:
    """Read and validate the policy file. Returns no rules on ANY problem."""
    try:
        raw = path.read_text(encoding="utf-8")
        return Policy.model_validate_json(raw).rules
    except ValidationError as exc:
        # Say where the problem is, without echoing the file's contents.
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'file'}: {error['msg']}"
            for error in exc.errors(include_input=False)
        )
        logger.error("invalid policy file %s, denying everything: %s", path, problems)
    except Exception as exc:
        logger.error(
            "could not read policy file %s, denying everything: %s", path, type(exc).__name__
        )
    return ()
