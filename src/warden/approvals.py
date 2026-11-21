"""Human approvals for actions that a rule marked `require_approval`.

The flow:
1. Agent asks; a rule says require_approval. Warden creates a PENDING approval,
   bound to the action's fingerprint (action_hash), and returns its approval_id.
2. A human lists pending approvals (with the arguments, so they can see what they
   are approving) and approves or denies one. Each can be decided only once.
3. Agent retries the SAME action with the approval_id. Warden allows it only if:
   the approval is APPROVED, the fingerprint matches exactly, it was never used
   before, and it hasn't expired. The check-and-mark-used step is a single locked
   operation, so two simultaneous retries can't both succeed.

Approvals live in memory only. Arguments may contain secrets, and they must be
shown to the human, so they are never written to disk. A restart drops every
approval: the agent simply has to ask again (fail closed).
"""

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from pydantic import JsonValue

from warden.models import ActionRequest, Decision, EvaluationResult

APPROVAL_TTL_SECONDS = 15 * 60
MAX_PENDING = 1000


class Status(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    USED = "used"


@dataclass
class Approval:
    approval_id: str
    agent_id: str
    tool: str
    arguments: dict[str, JsonValue]
    action_hash: str
    expires_at: float  # monotonic clock seconds
    status: Status = Status.PENDING


class DecideError(Exception):
    """Approve/deny failed. `not_found` = unknown or expired; else already decided."""

    def __init__(self, not_found: bool) -> None:
        super().__init__("not found" if not_found else "already decided")
        self.not_found = not_found


class ApprovalStore:
    """Thread-safe, in-memory approvals. Every method takes the lock."""

    def __init__(
        self,
        ttl_seconds: float = APPROVAL_TTL_SECONDS,
        max_pending: int = MAX_PENDING,
        clock: Callable[[], float] = time.monotonic,  # monotonic: immune to clock changes
    ) -> None:
        self._ttl = ttl_seconds
        self._max_pending = max_pending
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[str, Approval] = {}

    def _purge_expired(self, now: float) -> None:
        # Forgetting an expired id is safe: an unknown id is always refused.
        for key in [k for k, a in self._items.items() if a.expires_at <= now]:
            del self._items[key]

    def request(self, action: ActionRequest, action_hash: str) -> str | None:
        """Create (or reuse) a pending approval. None = too many pending."""
        with self._lock:
            now = self._clock()
            self._purge_expired(now)
            for a in self._items.values():
                if a.status is Status.PENDING and a.action_hash == action_hash:
                    return a.approval_id  # same action asked again: don't pile up
            pending = sum(a.status is Status.PENDING for a in self._items.values())
            if pending >= self._max_pending:
                return None
            approval_id = secrets.token_urlsafe(24)  # unguessable, 32 characters
            self._items[approval_id] = Approval(
                approval_id=approval_id,
                agent_id=action.agent_id,
                tool=action.tool,
                arguments=action.arguments,
                action_hash=action_hash,
                expires_at=now + self._ttl,
            )
            return approval_id

    def pending(self) -> list[tuple[Approval, float]]:
        """Pending approvals with seconds left, oldest first."""
        with self._lock:
            now = self._clock()
            self._purge_expired(now)
            items = [a for a in self._items.values() if a.status is Status.PENDING]
            return [(a, a.expires_at - now) for a in sorted(items, key=lambda a: a.expires_at)]

    def decide(
        self,
        approval_id: str,
        approve: bool,
        before_commit: Callable[[Approval, Status], None] = lambda a, s: None,
    ) -> Status:
        """Approve or deny a pending approval, exactly once.

        `before_commit` runs (under the lock) before the status changes. If it raises,
        nothing changes: used to make sure every human decision is audited first.
        """
        with self._lock:
            self._purge_expired(self._clock())
            approval = self._items.get(approval_id)
            if approval is None:
                raise DecideError(not_found=True)
            if approval.status is not Status.PENDING:
                raise DecideError(not_found=False)
            new_status = Status.APPROVED if approve else Status.DENIED
            before_commit(approval, new_status)
            approval.status = new_status
            return new_status

    def consume(self, approval_id: str, action_hash: str) -> bool:
        """Use an approval. True only once, only for the exact approved action."""
        with self._lock:
            self._purge_expired(self._clock())
            approval = self._items.get(approval_id)
            if approval is None or approval.status is not Status.APPROVED:
                return False
            # Constant-time compare; a mismatch does NOT burn the approval.
            if not secrets.compare_digest(approval.action_hash, action_hash):
                return False
            approval.status = Status.USED
            return True


def apply_approval(
    action: ActionRequest, result: EvaluationResult, store: ApprovalStore
) -> EvaluationResult:
    """Turn the engine's decision into the final answer, using approvals.

    Only require_approval is affected. An approval can never turn a DENY into ALLOW.
    """
    if result.decision is not Decision.REQUIRE_APPROVAL or result.action_hash is None:
        return result

    if action.approval_id is None:
        approval_id = store.request(action, result.action_hash)
        if approval_id is None:
            return EvaluationResult(
                decision=Decision.DENY,
                reason="too many pending approvals",
                matched_rule=result.matched_rule,
                action_hash=result.action_hash,
            )
        return EvaluationResult(
            decision=Decision.REQUIRE_APPROVAL,
            reason=result.reason,
            matched_rule=result.matched_rule,
            action_hash=result.action_hash,
            approval_id=approval_id,
        )

    if store.consume(action.approval_id, result.action_hash):
        return EvaluationResult(
            decision=Decision.ALLOW,
            reason=f"approved by a human ({result.reason})",
            matched_rule=result.matched_rule,
            action_hash=result.action_hash,
            approval_id=action.approval_id,
        )
    return EvaluationResult(
        decision=Decision.DENY,
        reason="approval not valid",
        matched_rule=result.matched_rule,
        action_hash=result.action_hash,
    )
