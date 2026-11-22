"""Every data model is strict (no silent type conversion) and frozen (can't change).

If someone removes strict=True or frozen=True from a model, these fail.
"""

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from warden.audit import AuditEntry, AuditEvent, EventKind
from warden.models import (
    ActionRequest,
    Condition,
    Decision,
    EvaluationResult,
    Rule,
    ToolSpec,
)
from warden.policy import Policy
from warden.settings import Settings

# (model, a valid example, a field to corrupt, a value lax mode would convert)
CASES: list[tuple[type[BaseModel], dict[str, Any], str, Any]] = [
    (ActionRequest, {"agent_id": "a", "tool": "t", "arguments": {}}, "tool", 5),
    (Condition, {"arg": "a", "op": "eq", "value": "x"}, "ignore_case", "yes"),
    (Rule, {"id": "r", "tool": "t", "effect": "allow"}, "id", 7),
    (ToolSpec, {"arguments": ["a"]}, "arguments", "a"),
    (EvaluationResult, {"decision": "deny", "reason": "x"}, "reason", 3),
    (Policy, {"rules": []}, "rules", "[]"),
    (
        AuditEntry,
        {
            "timestamp": "t",
            "agent_id": "a",
            "tool": "t",
            "decision": "deny",
            "reason": "r",
            "matched_rule": None,
            "action_hash": None,
        },
        "agent_id",
        5,
    ),
    (
        AuditEvent,
        {"timestamp": "t", "kind": "request_rejected", "reason": "r"},
        "http_status",
        "401",
    ),
]


@pytest.mark.parametrize(("model", "valid", "field", "lax_value"), CASES)
def test_models_refuse_loosely_typed_values(
    model: type[BaseModel], valid: dict[str, Any], field: str, lax_value: Any
) -> None:
    model.model_validate_json(json.dumps(valid))  # the valid example loads
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps({**valid, field: lax_value}))


@pytest.mark.parametrize(("model", "valid", "field", "lax_value"), CASES)
def test_models_refuse_unknown_fields(
    model: type[BaseModel], valid: dict[str, Any], field: str, lax_value: Any
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps({**valid, "surprise": 1}))


@pytest.mark.parametrize(("model", "valid", "field", "lax_value"), CASES)
def test_models_are_frozen(
    model: type[BaseModel], valid: dict[str, Any], field: str, lax_value: Any
) -> None:
    instance = model.model_validate_json(json.dumps(valid))
    with pytest.raises(ValidationError):
        setattr(instance, field, valid.get(field))


def test_python_construction_is_strict_too() -> None:
    with pytest.raises(ValidationError):
        EvaluationResult(decision="deny", reason=3)  # type: ignore[arg-type]
    assert EvaluationResult(decision=Decision.DENY, reason="x").decision is Decision.DENY
    assert AuditEvent(timestamp="t", kind=EventKind.AUDIT_PURGED, reason="r").reason == "r"


def test_settings_are_frozen() -> None:
    settings = Settings(policy=Path("p.json"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.port = 1  # type: ignore[misc]
