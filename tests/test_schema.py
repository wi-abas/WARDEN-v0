"""The JSON Schema for policy files: in sync with the code, and $schema is accepted."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from warden.cli import main, policy_schema
from warden.policy import SCHEMA_URL, Policy, load_policy

ROOT = Path(__file__).parent.parent


def test_committed_schema_matches_the_code() -> None:
    # If this fails, run: uv run warden schema > schemas/policy-v1.json
    assert (ROOT / "schemas/policy-v1.json").read_text() == policy_schema()


def test_schema_command_prints_it(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    assert json.loads(capsys.readouterr().out)["title"] == "Warden policy"


@pytest.mark.parametrize(
    "path", ["policies/default.json", "examples/demo-policy.json", "src/warden/starter_policy.json"]
)
def test_shipped_policies_link_the_schema(path: str) -> None:
    raw = json.loads((ROOT / path).read_text())
    assert raw["$schema"] == SCHEMA_URL
    assert load_policy(ROOT / path).rules  # loads fine with the $schema key


def test_schema_key_is_optional_and_ignored() -> None:
    with_key = Policy.model_validate_json(json.dumps({"$schema": "x", "rules": []}))
    without = Policy.model_validate_json(json.dumps({"rules": []}))
    assert with_key.rules == without.rules


@pytest.mark.parametrize("bad", [5, ["x"], "x" * 501])
def test_bad_schema_value_rejected(bad: object) -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate_json(json.dumps({"$schema": bad, "rules": []}))
