"""The policy engine: decides allow / deny / require_approval for one request.

Security properties (each one is tested in tests/test_engine.py):
- Default deny: if no rule matches the tool, the answer is DENY.
- Most restrictive wins: DENY beats REQUIRE_APPROVAL, which beats ALLOW.
- Fail closed: any unexpected error gives DENY, never ALLOW.
- Deterministic: no network, no files, no randomness, no LLM. Rule order does not matter.
- It only decides. It never runs the requested tool.
"""

import logging
from collections.abc import Iterable

from warden.models import ActionRequest, Decision, EvaluationResult, Rule

logger = logging.getLogger(__name__)

# Higher number = more restrictive. A Decision missing from this table raises
# KeyError, which the fail-closed handler in evaluate() turns into DENY.
_RESTRICTIVENESS = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.DENY: 2,
}


def evaluate(request: ActionRequest, rules: Iterable[Rule]) -> EvaluationResult:
    """Return Warden's decision for `request` under `rules`. Never raises."""
    try:
        return _evaluate(request, rules)
    except Exception as exc:
        # Log only the error type: the message could contain tool arguments (secrets).
        logger.error("policy evaluation failed: %s", type(exc).__name__)
        return EvaluationResult(decision=Decision.DENY, reason="evaluation error")


def _evaluate(request: ActionRequest, rules: Iterable[Rule]) -> EvaluationResult:
    matches = [rule for rule in rules if rule.tool == request.tool]

    if not matches:
        return EvaluationResult(decision=Decision.DENY, reason="no matching rule")

    # Pick the most restrictive rule. On a tie, the smallest rule id wins,
    # so the answer is the same whatever order the rules are listed in.
    winner = min(matches, key=lambda rule: (-_RESTRICTIVENESS[rule.effect], rule.id))

    return EvaluationResult(
        decision=winner.effect,
        reason=f"matched rule '{winner.id}'",
        matched_rule=winner.id,
    )
