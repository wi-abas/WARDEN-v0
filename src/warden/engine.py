"""The policy engine: decides allow / deny / require_approval for one request.

Security properties (each one is tested in tests/test_engine.py):
- Default deny: if no rule matches the tool, the answer is DENY.
- Tool specs: if the policy lists a tool's arguments, any other argument, or a
  missing required one, is denied before any rule runs.
- Argument conditions ("when"): a rule matches only if ALL its conditions hold.
- Never a looser answer because something is missing or odd:
  - A MISSING argument counts as "condition holds" for deny / require_approval
    rules (they apply) and as "doesn't hold" for allow rules (they don't).
    So "deny when recipient endswith evil.com" can't be dodged by leaving
    recipient out. Use the `exists` / `missing` ops to say it explicitly.
  - An argument that can't be checked (wrong type, or a ".." path for
    startswith) denies the whole request, so a "deny" rule can't be dodged
    by sending "50000" as text instead of a number.
- Most restrictive wins: DENY beats REQUIRE_APPROVAL, which beats ALLOW.
- Fail closed: any unexpected error gives DENY, never ALLOW.
- Deterministic: no network, no files, no randomness, no LLM. Rule order does not matter.
- It only decides. It never runs the requested tool.
"""

import logging
from collections.abc import Iterable, Mapping

from pydantic import JsonValue

from warden.fingerprint import fingerprint
from warden.models import (
    NUMBER_OPS,
    ActionRequest,
    Condition,
    Decision,
    EvaluationResult,
    Op,
    Rule,
    ToolSpec,
    is_number,
)

logger = logging.getLogger(__name__)

# Higher number = more restrictive. A Decision missing from this table raises
# KeyError, which the fail-closed handler in evaluate() turns into DENY.
_RESTRICTIVENESS = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.DENY: 2,
}


class _MissingArgument(Exception):
    """The argument a condition looks at is absent from the request."""


class _UncheckableArgument(Exception):
    """An argument exists but can't be compared safely (wrong type, "..", ...)."""

    def __init__(self, arg: str) -> None:
        super().__init__(arg)
        self.arg = arg


def _comparable(a: JsonValue, b: JsonValue) -> bool:
    """Both numbers, or exactly the same type. Avoids Python's True == 1."""
    return (is_number(a) and is_number(b)) or type(a) is type(b)


def _fold(value: JsonValue, condition: Condition) -> JsonValue:
    """Lower-case text (casefold handles e.g. German ß) when ignore_case is set."""
    if condition.ignore_case and isinstance(value, str):
        return value.casefold()
    return value


def _holds(condition: Condition, arguments: dict[str, JsonValue]) -> bool:
    present = condition.arg in arguments
    if condition.op is Op.EXISTS:
        return present
    if condition.op is Op.MISSING:
        return not present
    if not present:
        raise _MissingArgument
    actual = arguments[condition.arg]
    expected = condition.value
    op = condition.op

    if op in NUMBER_OPS:
        if not is_number(actual):
            raise _UncheckableArgument(condition.arg)
        if op is Op.GT:
            return actual > expected
        if op is Op.GTE:
            return actual >= expected
        if op is Op.LT:
            return actual < expected
        return actual <= expected  # Op.LTE

    if op in {Op.STARTSWITH, Op.ENDSWITH}:
        # ".." could escape a path prefix: "/data/../etc/passwd" starts with "/data/".
        if not isinstance(actual, str) or (op is Op.STARTSWITH and ".." in actual):
            raise _UncheckableArgument(condition.arg)
        text, affix = _fold(actual, condition), _fold(expected, condition)
        return text.startswith(affix) if op is Op.STARTSWITH else text.endswith(affix)

    # eq / neq / in: the argument must have the same type as the policy value(s).
    choices = expected if op is Op.IN else [expected]
    if not any(_comparable(actual, choice) for choice in choices):
        raise _UncheckableArgument(condition.arg)
    found = any(
        _comparable(actual, c) and _fold(actual, condition) == _fold(c, condition) for c in choices
    )
    if op is Op.NEQ:
        return not found
    return found  # Op.EQ, Op.IN


def _rule_matches(rule: Rule, request: ActionRequest) -> bool:
    if rule.tool != request.tool:
        return False
    # Check every condition (no short-circuit), so an uncheckable argument is always
    # caught, whatever order the conditions are written in.
    results = [_condition_result(rule, condition, request) for condition in rule.when]
    return all(results)


def _condition_result(rule: Rule, condition: Condition, request: ActionRequest) -> bool:
    try:
        return _holds(condition, request.arguments)
    except _MissingArgument:
        # Fail closed: restrictive rules still apply, allow rules don't.
        return rule.effect is not Decision.ALLOW


def evaluate(
    request: ActionRequest,
    rules: Iterable[Rule],
    tools: Mapping[str, ToolSpec] | None = None,
) -> EvaluationResult:
    """Return Warden's decision for `request` under `rules` and tool specs. Never raises."""
    try:
        return _evaluate(request, rules, tools or {})
    except Exception as exc:
        # Log only the error type: the message could contain tool arguments (secrets).
        logger.error("policy evaluation failed: %s", type(exc).__name__)
        return EvaluationResult(decision=Decision.DENY, reason="evaluation error")


def _spec_problem(request: ActionRequest, spec: ToolSpec) -> str | None:
    if any(name not in spec.arguments for name in request.arguments):
        # The name comes from the agent (untrusted, could hold a secret): don't echo it.
        return "unexpected argument"
    for name in spec.required:  # names from the policy file: safe to show
        if name not in request.arguments:
            return f"missing required argument '{name}'"
    return None


def _evaluate(
    request: ActionRequest, rules: Iterable[Rule], tools: Mapping[str, ToolSpec]
) -> EvaluationResult:
    action_hash = fingerprint(request)

    spec = tools.get(request.tool)
    if spec is not None:
        problem = _spec_problem(request, spec)
        if problem is not None:
            return EvaluationResult(decision=Decision.DENY, reason=problem, action_hash=action_hash)
    try:
        matches = [rule for rule in rules if _rule_matches(rule, request)]
    except _UncheckableArgument as exc:
        # exc.arg is the argument NAME from the policy file, never its value.
        return EvaluationResult(
            decision=Decision.DENY,
            reason=f"argument '{exc.arg}' could not be checked",
            action_hash=action_hash,
        )

    if not matches:
        return EvaluationResult(
            decision=Decision.DENY, reason="no matching rule", action_hash=action_hash
        )

    # Pick the most restrictive rule. On a tie, the smallest rule id wins,
    # so the answer is the same whatever order the rules are listed in.
    winner = min(matches, key=lambda rule: (-_RESTRICTIVENESS[rule.effect], rule.id))

    return EvaluationResult(
        decision=winner.effect,
        reason=winner.message or f"matched rule '{winner.id}'",
        matched_rule=winner.id,
        action_hash=action_hash,
    )
