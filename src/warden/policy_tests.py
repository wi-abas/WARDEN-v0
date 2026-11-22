"""`warden test`: check a policy against example requests, like unit tests for rules.

A test file (JSON):

    {
      "policy": "../policies/default.json",
      "cases": [
        {"name": "read in workspace",
         "request": {"tool": "read_file", "arguments": {"path": "/workspace/a.txt"}},
         "expect": "allow", "rule": "read-workspace"},
        {"name": "never delete",
         "request": {"tool": "delete_file", "arguments": {"path": "/workspace/a"}},
         "expect": "deny"}
      ]
    }

- "policy" is relative to the test file (or give --policy FILE).
- "request" is what an agent would send: tool, arguments, optional agent_id
  (default "policy-test"). It goes through the same validation as /v1/evaluate.
- "expect" is the decision; "rule" (optional) the rule id that must decide, or null
  for "no rule matched"; "reason" (optional) the exact reason text.

Runs the real engine directly: no server, no audit log, no approvals, no rate limits.
A require_approval case passes when the engine asks for approval.
"""

import json
import sys
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from warden.engine import evaluate
from warden.models import AGENT_ID_PATTERN, ActionRequest, Decision
from warden.policy import (
    DuplicateKeyError,
    Policy,
    describe_errors,
    no_duplicate_keys,
    parse_policy,
)

MAX_TEST_FILE_BYTES = 5 * 1024 * 1024
MAX_CASES = 10_000


class CaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(default="policy-test", pattern=AGENT_ID_PATTERN)
    tool: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class PolicyCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Annotated[str, Field(min_length=1, max_length=200)]
    request: CaseRequest
    expect: Decision
    rule: str | None = None  # checked only if given; null = "no rule matched"
    reason: str | None = None


class CaseFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy: str | None = None
    cases: list[PolicyCase] = Field(min_length=1, max_length=MAX_CASES)


class PolicyTestError(Exception):
    """The test file or policy can't be used; the message says why."""


def load_tests(path: Path) -> CaseFile:
    try:
        if path.stat().st_size > MAX_TEST_FILE_BYTES:
            raise PolicyTestError(f"{path} is larger than 5 MB")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyTestError(f"can't read {path}: {type(exc).__name__}") from exc
    try:
        data = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        tests = CaseFile.model_validate(data)
    except json.JSONDecodeError as exc:
        raise PolicyTestError(f"{path} isn't valid JSON (line {exc.lineno})") from exc
    except RecursionError as exc:
        raise PolicyTestError(f"{path} is nested too deeply") from exc
    except DuplicateKeyError as exc:
        raise PolicyTestError(f"{path}: {exc}") from exc
    except ValidationError as exc:
        raise PolicyTestError(f"{path}: {'; '.join(describe_errors(exc))}") from exc
    names = [case.name for case in tests.cases]
    if len(set(names)) != len(names):
        raise PolicyTestError(f"{path}: two cases have the same name")
    return tests


def load_policy_strict(path: Path) -> Policy:
    """Unlike the server, a broken policy is an error here, not "deny everything"."""
    try:
        return parse_policy(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyTestError(f"can't read policy {path}: {type(exc).__name__}") from exc
    except DuplicateKeyError as exc:
        raise PolicyTestError(f"policy {path}: {exc}") from exc
    except ValidationError as exc:
        raise PolicyTestError(f"policy {path}: {'; '.join(describe_errors(exc))}") from exc


def run_case(policy: Policy, case: PolicyCase) -> str | None:
    """None if the case passes, otherwise what went wrong."""
    try:
        # Through JSON, exactly like a real request on the wire.
        request = ActionRequest.model_validate_json(json.dumps(case.request.model_dump()))
    except ValidationError as exc:
        # The server answers invalid input with deny, no rule.
        if case.expect is Decision.DENY and case.rule is None and case.reason is None:
            return None
        return f"rejected as invalid input ({'; '.join(describe_errors(exc))})"
    result = evaluate(request, policy.rules, policy.tools)
    problems = []
    if result.decision is not case.expect:
        problems.append(f"expected {case.expect.value}, got {result.decision.value}")
    if "rule" in case.model_fields_set and result.matched_rule != case.rule:
        problems.append(f"expected rule {case.rule!r}, got {result.matched_rule!r}")
    if case.reason is not None and result.reason != case.reason:
        problems.append(f"expected reason {case.reason!r}, got {result.reason!r}")
    if not problems:
        return None
    return "; ".join(problems) + f" (reason: {result.reason})"


def run(test_path: Path, policy_path: Path | None = None) -> int:
    """`warden test FILE [--policy FILE]`: 0 all passed, 1 a case failed, 2 can't run."""
    try:
        tests = load_tests(test_path)
        if policy_path is None:
            if tests.policy is None:
                raise PolicyTestError(f'{test_path} has no "policy"; give --policy FILE')
            policy_path = test_path.parent / tests.policy
        policy = load_policy_strict(policy_path)
    except PolicyTestError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    failed = 0
    for case in tests.cases:
        problem = run_case(policy, case)
        if problem is None:
            print(f"PASS  {case.name}")
        else:
            failed += 1
            print(f"FAIL  {case.name}: {problem}")
    total = len(tests.cases)
    print(f"\n{total - failed} passed, {failed} failed ({policy_path}).")
    return 1 if failed else 0
