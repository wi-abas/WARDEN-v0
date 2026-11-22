"""Per-agent rate limits and approval quotas. Deterministic: a clock, no randomness.

The policy file may have a "limits" section:
    "limits": {
      "default": {"requests_per_minute": 600, "max_pending_approvals": 50},
      "agents": {"billing-agent": {"requests_per_minute": 30}}
    }
A value set for the agent wins, then "default", then the built-in defaults below.
See docs/design/rate-limits.md.
"""

import threading
import time
from collections.abc import Callable
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from warden.models import AGENT_ID_PATTERN

DEFAULT_REQUESTS_PER_MINUTE = 600
DEFAULT_MAX_PENDING_APPROVALS = 50
MAX_TRACKED_AGENTS = 10_000


class LimitSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    requests_per_minute: int | None = Field(default=None, ge=1, le=100_000)
    # 0 = this agent may never wait for approval (require_approval becomes deny).
    max_pending_approvals: int | None = Field(default=None, ge=0, le=1000)


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    default: LimitSpec = LimitSpec()
    agents: dict[Annotated[str, Field(pattern=AGENT_ID_PATTERN)], LimitSpec] = Field(
        default_factory=dict, max_length=1000
    )

    def requests_per_minute(self, agent_id: str) -> int:
        own = self.agents.get(agent_id, LimitSpec()).requests_per_minute
        fallback = self.default.requests_per_minute
        return own or fallback or DEFAULT_REQUESTS_PER_MINUTE

    def max_pending_approvals(self, agent_id: str) -> int:
        own = self.agents.get(agent_id, LimitSpec()).max_pending_approvals
        if own is not None:
            return own
        fallback = self.default.max_pending_approvals
        return fallback if fallback is not None else DEFAULT_MAX_PENDING_APPROVALS


class _Bucket:
    __slots__ = ("tokens", "updated")

    def __init__(self, tokens: float, updated: float) -> None:
        self.tokens = tokens
        self.updated = updated


class RateLimiter:
    """A token bucket per agent: up to N requests at once, refilled at N per minute."""

    def __init__(
        self,
        limits: Limits,
        clock: Callable[[], float] = time.monotonic,
        max_agents: int = MAX_TRACKED_AGENTS,
    ) -> None:
        self._limits = limits
        self._clock = clock
        self._max_agents = max_agents
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    def acquire(self, agent_id: str) -> float:
        """Take one request from the agent's bucket. Returns 0 if allowed, otherwise
        the seconds until the next request would be allowed."""
        capacity = self._limits.requests_per_minute(agent_id)
        rate = capacity / 60.0  # per second
        with self._lock:
            now = self._clock()
            bucket = self._buckets.get(agent_id)
            if bucket is None:
                if len(self._buckets) >= self._max_agents and not self._forget_idle(now):
                    return 60.0  # can't track another agent: fail closed
                bucket = self._buckets[agent_id] = _Bucket(float(capacity), now)
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(float(capacity), bucket.tokens + elapsed * rate)
            bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return 0.0
            return (1.0 - bucket.tokens) / rate

    def _forget_idle(self, now: float) -> bool:
        """Drop buckets that have refilled completely (their agents are idle)."""
        idle = []
        for agent, bucket in self._buckets.items():
            capacity = self._limits.requests_per_minute(agent)
            if bucket.tokens + (now - bucket.updated) * capacity / 60.0 >= capacity:
                idle.append(agent)
        for agent in idle:
            del self._buckets[agent]
        return bool(idle)
