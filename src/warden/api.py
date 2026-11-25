"""The HTTP API that agents talk to. A thin layer: no security logic lives here.

Endpoints:
- GET  /health       -> "ok", or "degraded" (HTTP 503) when no rules loaded: everything is denied
- POST /v1/evaluate  -> send an EvaluateRequest, get an EvaluationResult
                        (with --agents: needs "Authorization: Bearer <agent token>")

Admin only (header "X-Warden-Admin-Key", printed in the terminal at startup):
- GET  /v1/approvals                  -> pending approvals, with their arguments
- POST /v1/approvals/{id}/approve     -> approve one (once); body {"action_hash": ...}
- POST /v1/approvals/{id}/deny        -> deny one (once); body {"action_hash": ...},
                                         or no body to revoke an approved, unused one
- GET  /v1/approvals?group=true       -> the same, grouped by (agent_id, tool)
- POST /v1/approvals/decide           -> approve or deny several by id, all or nothing
- GET  /v1/approvals?ids=A,B&agent_id=X&tool=Y -> only those (narrows the view only)
- GET  /v1/approvals?max_age_seconds=N -> only those asked for in the last N seconds
- GET  /v1/approvals?status=rejected  -> rejections that still stand (no arguments)
- POST /v1/approvals/{id}/lift        -> lift a rejection: the agent may ask again

Every decision is written to the audit log before it is returned. If the
audit log can't be written, the answer is deny (503): no unrecorded allows.

Every error response still carries "decision": "deny", so a careless client
that only reads the decision field fails closed.

Run it with `uv run warden` (listens on 127.0.0.1 only: this machine, not the network).
"""

import copy
import json
import logging
import logging.config
import math
import re
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

import uvicorn
import uvicorn.config
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from warden import __version__, audit
from warden.agents import AgentRegistry, AgentsError, load_agents
from warden.approvals import (
    MAX_GROUP,
    Approval,
    ApprovalDB,
    ApprovalStore,
    DecideError,
    GroupDecideError,
    Status,
    apply_approval,
)
from warden.audit import AuditEntry, AuditEvent, AuditLog, EventKind, SQLiteAuditLog
from warden.engine import evaluate
from warden.limits import RateLimiter
from warden.models import (
    AGENT_ID_PATTERN,
    APPROVAL_ID_PATTERN,
    TOOL_NAME_PATTERN,
    ActionRequest,
    Decision,
    EvaluateRequest,
    EvaluationResult,
)
from warden.policy import (
    DEFAULT_POLICY_PATH,
    DuplicateKeyError,
    Policy,
    load_policy,
    no_duplicate_keys,
    per_agent_problem,
)
from warden.settings import Settings
from warden.unicode_safety import is_invisible

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
MAX_BODY_BYTES = 64 * 1024  # 64 KB is far more than any real tool call needs
REJECTIONS_PER_MINUTE = 60
# Rejected requests are recorded by a background worker, never on the server's main
# loop: if the database is locked (e.g. someone has it open), a synchronous write would
# freeze EVERY request for up to 5 seconds. Tests switch this off to read events at once.
RECORD_REJECTIONS_IN_BACKGROUND = True  # mutation-ok: speed only


def _deny_response(status_code: int, reason: str) -> JSONResponse:
    body = EvaluationResult(decision=Decision.DENY, reason=reason).model_dump(mode="json")
    return JSONResponse(status_code=status_code, content=body)


class BodySizeLimit:
    """Rejects oversized requests BEFORE their body is read.

    Requests with a body must declare their size up front (Content-Length).
    Bodies with no declared size (chunked uploads) are refused, because their
    size can't be checked before reading them. The server never reads more
    bytes than Content-Length says.
    """

    def __init__(
        self,
        app: ASGIApp,
        max_bytes: int = MAX_BODY_BYTES,
        on_reject: Callable[[Scope, int, str], None] = lambda scope, status, reason: None,
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.on_reject = on_reject

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            length = headers.get(b"content-length")
            if length is None and b"transfer-encoding" in headers:
                await self._reject(scope, receive, send, 411, "content-length required")
                return
            if length is not None and (not length.isdigit() or int(length) > self.max_bytes):
                await self._reject(scope, receive, send, 413, "request too large")
                return
        await self.app(scope, receive, send)

    async def _reject(
        self, scope: Scope, receive: Receive, send: Send, status: int, reason: str
    ) -> None:
        self.on_reject(scope, status, reason)
        await _deny_response(status, reason)(scope, receive, send)


class DuplicateKeyCheck:
    """Refuses JSON bodies that repeat a key, e.g. {"tool": "read_file", "tool": "delete_file"}.

    Parsers disagree on which copy wins (Python keeps the last, others the first), so the
    tool that finally runs could act on a different value than the one Warden checked.
    For the same reason it refuses a body with a UTF-8 byte order mark, or in UTF-16/32
    (Python's json.loads quietly accepts both, other parsers strip or fail): the body
    must be plain UTF-8.
    Runs after BodySizeLimit, so the body it reads is at most MAX_BODY_BYTES.
    """

    def __init__(
        self,
        app: ASGIApp,
        on_reject: Callable[[Scope, int, str], None] = lambda scope, status, reason: None,
    ) -> None:
        self.app = app
        self.on_reject = on_reject

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":  # client went away
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        # JSON in UTF-8 never holds a raw NUL byte (it must be escaped); UTF-16/32 does.
        if body.startswith(b"\xef\xbb\xbf") or b"\x00" in body:
            reason = "request body must be UTF-8 without a byte order mark"
            self.on_reject(scope, 422, reason)
            await _deny_response(422, reason)(scope, receive, send)
            return
        try:
            json.loads(body, object_pairs_hook=no_duplicate_keys)
        except DuplicateKeyError:
            self.on_reject(scope, 422, "duplicate key in request")
            await _deny_response(422, "duplicate key in request")(scope, receive, send)
            return
        except (ValueError, RecursionError):
            # Not valid JSON, or nested too deeply for Python's parser: request
            # validation reports it (as 422, not a 500 "internal error").
            pass

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True  # mutation-ok: the app reads the body only once
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


# Host names a request may be addressed to. Anything else is refused, which stops
# "DNS rebinding": a malicious web page pointing its own domain at 127.0.0.1 to
# talk to Warden from your browser.
ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")


def _host_name(raw: bytes) -> str:
    """'127.0.0.1:8000' -> '127.0.0.1', '[::1]:8000' -> '::1'."""
    host = raw.decode("latin-1").strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else ""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host  # mutation-ok: one ":"


class HostCheck:
    """Refuses requests whose Host header isn't one of `allowed`."""

    def __init__(
        self,
        app: ASGIApp,
        allowed: tuple[str, ...] = ALLOWED_HOSTS,
        on_reject: Callable[[Scope, int, str], None] = lambda scope, status, reason: None,
    ) -> None:
        self.app = app
        self.allowed = allowed
        self.on_reject = on_reject

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            # Exactly one Host header: with two, a dict keeps the last while a proxy or
            # framework in front might have used the first.
            hosts = [value for name, value in scope["headers"] if name.lower() == b"host"]
            if len(hosts) != 1 or _host_name(hosts[0]) not in self.allowed:
                self.on_reject(scope, 400, "host not allowed")
                await _deny_response(400, "host not allowed")(scope, receive, send)
                return
        await self.app(scope, receive, send)


class CrashGuard:
    """Answers 500 deny when anything inside crashes, and logs only the error's type:
    never its message or a stack trace, which may hold tool arguments. The exception
    stops here, so the server can't log it either."""

    def __init__(
        self,
        app: ASGIApp,
        on_reject: Callable[[Scope, int, str], None] = lambda scope, status, reason: None,
    ) -> None:
        self.app = app
        self.on_reject = on_reject

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def watched_send(message: Message) -> None:
            nonlocal started
            started = True
            await send(message)

        try:
            await self.app(scope, receive, watched_send)
        except Exception as exc:
            logger.error("unexpected error handling request: %s", type(exc).__name__)
            self.on_reject(scope, 500, "internal error")
            if not started:  # else: the server closes the unfinished answer
                await _deny_response(500, "internal error")(scope, receive, send)


def _is_deceptive_char(ch: str) -> bool:
    """Characters that make text DISPLAY differently from what it is: invisible or
    control characters, direction overrides (U+202E reverses what follows), and
    compatibility look-alikes such as the full-width "ｅ"."""
    return is_invisible(ch) or unicodedata.normalize("NFKC", ch) != ch


# What an escape looks like, written out as plain text: shown raw, the text "\\u200b"
# would look exactly like an escaped zero-width space. "\\U" only counts with 8 hex
# digits (the shape of our own escapes), so "C:\\Users" stays readable.
_LOOKS_ESCAPED = re.compile(r"\\(?:u|U[0-9A-Fa-f]{8})")


def _needs_escape(text: str, index: int) -> bool:
    """Deceptive characters, and a real backslash that would read as an escape: otherwise
    two different keys could display the same and one would hide the other."""
    return _is_deceptive_char(text[index]) or _LOOKS_ESCAPED.match(text, index) is not None


def _escape(ch: str) -> str:
    """\\uXXXX, or \\UXXXXXXXX above U+FFFF. Always a fixed length: "\\u1d400" could be
    U+1D400, or U+1D40 followed by "0"."""
    code = ord(ch)
    return f"\\U{code:08x}" if code > 0xFFFF else f"\\u{code:04x}"


def _display_safe(value: JsonValue, warnings: list[str]) -> JsonValue:
    """A copy of `value` with deceptive characters written as visible escapes (\\u202e),
    so an approver can't be shown something other than the real action. One-to-one:
    two different texts never display the same."""
    if isinstance(value, str):
        escape = [_needs_escape(value, i) for i in range(len(value))]
        if not any(escape):
            return value
        warnings.append("contains hidden or look-alike characters (shown as \\uXXXX)")
        return "".join(_escape(ch) if hit else ch for ch, hit in zip(value, escape, strict=True))
    if isinstance(value, list):
        return [_display_safe(item, warnings) for item in value]
    if isinstance(value, dict):
        out: dict[str, JsonValue] = {}
        for key, item in value.items():
            safe_key = str(_display_safe(key, warnings))
            if safe_key in out:  # pragma: no cover - escaping is one-to-one (tested)
                # Never overwrite: a vanished argument would be approved unseen.
                raise ValueError("two argument names would display the same")
            out[safe_key] = _display_safe(item, warnings)
        return out
    return value


ActionHash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
# ?max_age_seconds on GET /v1/approvals: at most a week (approvals live 15 minutes).
MAX_AGE_QUERY_SECONDS = 7 * 24 * 3600
# ?ids=A,B,C on GET /v1/approvals: 1 to MAX_GROUP approval ids, comma-separated.
_ID = APPROVAL_ID_PATTERN.strip("^$")
IDS_QUERY_PATTERN = rf"^{_ID}(,{_ID}){{0,{MAX_GROUP - 1}}}$"


HASH_REQUIRED = "action_hash required: list the approvals and send the action_hash you were shown"
HASHES_REQUIRED = (
    "action_hashes required: list the approvals and send the action_hash you were shown for each"
)


class SingleDecision(BaseModel):
    """Body of POST /v1/approvals/{id}/approve|deny: the action_hash the human was shown,
    which must match the approval (proof the list was fetched). Required to approve and
    to reject a pending approval; revoking an approved one works without it (no body, or
    `{}`; checked if sent). `{}` means "no action_hash"; any other key is refused."""

    # mutation-ok: strict/frozen can't matter: one string field, JSON never coerces to it
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    action_hash: ActionHash | None = None

    @field_validator("action_hash", mode="before")
    @classmethod
    def not_null(cls, value: object) -> object:
        # Only runs for a SENT value: an explicit null is a mistake, not "no hash".
        if value is None:
            raise ValueError("action_hash can't be null (leave it out instead)")
        return value


class GroupDecision(BaseModel):
    """Body of POST /v1/approvals/decide: the exact approvals the human decides, and the
    action_hash shown for each (same order): you can't approve or reject a group you
    haven't listed."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    ids: list[Annotated[str, StringConstraints(pattern=APPROVAL_ID_PATTERN)]] = Field(
        min_length=1, max_length=MAX_GROUP
    )
    action_hashes: list[ActionHash] | None = Field(default=None, max_length=MAX_GROUP)
    approve: bool

    @field_validator("ids")
    @classmethod
    def no_duplicates(cls, ids: list[str]) -> list[str]:
        if len(set(ids)) != len(ids):
            raise ValueError("an id is listed more than once")
        return ids

    @model_validator(mode="after")
    def hashes_fit(self) -> "GroupDecision":
        # Missing action_hashes is refused in decide_group, with a clear message.
        if self.action_hashes is not None and len(self.action_hashes) != len(self.ids):
            raise ValueError("one action_hash per id")
        return self


class StartupError(Exception):
    """Warden can't start; the message says why (and never contains secrets)."""


class _AdminKeyError(Exception):
    pass


class _RateLimited(Exception):
    def __init__(self, retry_after: float) -> None:
        super().__init__("rate limit exceeded")
        self.retry_after = retry_after


class _AgentTokenError(Exception):
    """No valid agent token (401), or a body agent_id that contradicts it (403)."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass
class _Warden:
    """Everything the routes need, with one method per job. Routes stay one-liners."""

    policy: Policy
    audit_log: AuditLog
    approvals: ApprovalStore
    admin_key: str
    # None = no agent tokens: agent_id is self-declared (the old behaviour).
    agents: AgentRegistry | None = None
    limiter: RateLimiter | None = None  # None = built from the policy's limits
    # Rejected requests are recorded at most this many per minute, so a flood of bad
    # requests can't fill the disk. The rest are counted and summarised in one event.
    rejections_per_minute: int = REJECTIONS_PER_MINUTE
    clock: Callable[[], float] = time.monotonic
    record_in_background: bool = True  # mutation-ok: speed only
    _events: ThreadPoolExecutor = field(
        default_factory=lambda: ThreadPoolExecutor(
            # mutation-ok: one worker keeps events in order; tests can't see the order race
            max_workers=1,
            thread_name_prefix="warden-events",
        )
    )
    _limit_lock: threading.Lock = field(default_factory=threading.Lock)
    _window_start: float = -1e18
    _window_count: int = 0  # mutation-ok: reset on the first rejection
    _suppressed: int = 0

    def __post_init__(self) -> None:
        if self.limiter is None:
            self.limiter = RateLimiter(self.policy.limits)
        # How long a human "no" sticks, per agent, from the policy's limits.
        self.approvals.rejection_window = self.policy.limits.rejection_window_seconds

    # --- Access control and rejected requests ------------------------------------------

    def require_admin(self, x_warden_admin_key: str | None = Header(default=None)) -> None:
        if x_warden_admin_key is None or not secrets.compare_digest(
            x_warden_admin_key.encode(), self.admin_key.encode()
        ):
            raise _AdminKeyError

    def record_rejection(self, scope: Scope, status: int, reason: str) -> None:
        """Audit a refused request: method and URL path only, never the body."""
        if not self._within_rejection_limit():
            return
        self._emit(
            AuditEvent.now(
                EventKind.REQUEST_REJECTED,
                reason,
                http_status=status,
                method=str(scope.get("method", "")),
                path=str(scope.get("path", "")),
            )
        )

    def _within_rejection_limit(self) -> bool:
        """True if this rejection may be recorded. Writes a summary when a new minute
        starts after some were suppressed."""
        with self._limit_lock:
            now = self.clock()
            suppressed = 0
            if now - self._window_start >= 60:
                suppressed, self._suppressed = self._suppressed, 0
                self._window_start, self._window_count = now, 0
            allowed = self._window_count < self.rejections_per_minute
            if allowed:
                self._window_count += 1
            else:
                self._suppressed += 1
        if suppressed:
            self._emit(
                AuditEvent.now(
                    EventKind.REQUEST_REJECTED,
                    f"{suppressed} more rejected requests not recorded (rate limit)",
                )
            )
        return allowed

    def _emit(self, event: AuditEvent) -> None:
        """Record an event that doesn't change the answer, without blocking the caller."""
        if self.record_in_background:
            self._events.submit(self._record_event_safely, event)
        else:
            self._record_event_safely(event)

    def flush_events(self, timeout: float = 10) -> None:  # mutation-ok: timeout
        """Wait until queued events are written (tests, shutdown)."""
        self._events.submit(lambda: None).result(timeout)

    def reject(self, request: Request, status: int, reason: str) -> JSONResponse:
        self.record_rejection(request.scope, status, reason)
        return _deny_response(status, reason)

    def _record_event_safely(self, event: AuditEvent) -> None:
        """For events that don't change the answer (it's already deny / an error)."""
        try:
            self.audit_log.record_event(event)
        except Exception as exc:
            logger.error("audit event write failed: %s", type(exc).__name__)

    # --- Agents ------------------------------------------------------------------------

    def health(self) -> JSONResponse:
        # No rules means every request is denied: Warden runs, but isn't doing its job.
        # 503 lets monitoring tools notice without reading the body.
        if not self.policy.rules:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "rules_loaded": 0,
                    "reason": "no rules loaded, every request is denied (check the policy file)",
                },
            )
        return JSONResponse(content={"status": "ok", "rules_loaded": len(self.policy.rules)})

    def identify(self, body: EvaluateRequest, authorization: str | None) -> ActionRequest:
        """Settle WHO is asking. With agent tokens, the token decides, never the body."""
        if self.agents is None:
            if body.agent_id is None:
                raise _AgentTokenError(422, "agent_id required")
            agent_id = body.agent_id
        else:
            token_agent = self.agents.identify_header(authorization)
            if token_agent is None:
                raise _AgentTokenError(401, "agent token missing or wrong")
            if body.agent_id is not None and body.agent_id != token_agent:
                raise _AgentTokenError(403, "agent_id does not match the agent token")
            agent_id = token_agent
        return ActionRequest(
            agent_id=agent_id,
            tool=body.tool,
            arguments=body.arguments,
            approval_id=body.approval_id,
        )

    def evaluate(
        self, body: EvaluateRequest, authorization: str | None = Header(default=None)
    ) -> EvaluationResult | JSONResponse:
        action = self.identify(body, authorization)
        if self.limiter is not None and (wait := self.limiter.acquire(action.agent_id)):
            raise _RateLimited(wait)
        decision = evaluate(action, self.policy.rules, self.policy.tools)
        quota = self.policy.limits.max_pending_approvals(action.agent_id)
        result = apply_approval(action, decision, self.approvals, agent_limit=quota)
        try:
            self.audit_log.record(AuditEntry.from_decision(action, result))
        except Exception as exc:
            logger.error("audit log write failed, denying: %s", type(exc).__name__)
            # mutation-ok: restore() only acts on a USED approval, i.e. exactly this case
            if result.decision is Decision.ALLOW and result.approval_id is not None:
                # The approval was used for an allow the agent will never get.
                self.approvals.restore(result.approval_id)
            return _deny_response(503, "audit log unavailable")
        # Safe to log: tool names and rule ids are pattern-checked. Never log arguments.
        logger.info(
            "decision=%s tool=%s rule=%s", result.decision, action.tool, result.matched_rule
        )
        return result

    # --- Humans (admin) ----------------------------------------------------------------

    def list_approvals(
        self,
        request: Request,
        group: bool = False,
        status: Literal["pending", "rejected"] = "pending",
        ids: Annotated[str | None, Query(pattern=IDS_QUERY_PATTERN)] = None,
        agent_id: Annotated[str | None, Query(pattern=AGENT_ID_PATTERN)] = None,
        tool: Annotated[str | None, Query(pattern=TOOL_NAME_PATTERN)] = None,
        max_age_seconds: Annotated[int | None, Query(ge=1, le=MAX_AGE_QUERY_SECONDS)] = None,
    ) -> JsonValue | JSONResponse:
        """Pending approvals, every one in full. With group=true: grouped by
        (agent_id, tool), never just a count (see docs/design/group-approvals.md).

        `ids` (comma-separated, at most 100), `agent_id` and `tool` only narrow what is
        SHOWN, so a reviewer can still see and decide a few approvals while an agent
        floods the queue. Decisions still take exact ids; unknown ids are just absent.
        `max_age_seconds` narrows it to approvals asked for at most that long ago.

        Promise (tested): this view shows only PENDING, UNEXPIRED approvals. Approved,
        rejected, used and expired ones never appear here (see
        docs/design/approval-hygiene.md), so old decisions can't be swept in again.

        status=rejected: the rejections that still stand (no arguments: none are kept).
        """
        wanted = set(ids.split(",")) if ids else None

        def shown(a: Approval, age: float = 0.0) -> bool:
            return (
                (wanted is None or a.approval_id in wanted)
                and (max_age_seconds is None or age <= max_age_seconds)
                and (agent_id is None or a.agent_id == agent_id)
                and (tool is None or a.tool == tool)
            )

        if status == "rejected":
            if group:
                return self.reject(request, 422, "group is only for pending approvals")
            if max_age_seconds is not None:
                return self.reject(request, 422, "max_age_seconds is only for pending approvals")
            return [
                _rejection_item(a, left, since)
                for a, left, since in self.approvals.rejections()
                if shown(a)
            ]
        if not group:
            return [
                _approval_item(a, left)
                for a, left in self.approvals.pending()
                if shown(a, _age(a, left))
            ]
        groups: list[JsonValue] = []
        for (group_agent, group_tool), items in self.approvals.pending_groups():
            kept: list[JsonValue] = [
                _approval_item(a, left) for a, left in items if shown(a, _age(a, left))
            ]
            if kept:
                groups.append(
                    {
                        "agent_id": group_agent,
                        "tool": group_tool,
                        "count": len(kept),
                        "approvals": kept,
                    }
                )
        return {"groups": groups}

    def decide(
        self,
        approval_id: str,
        approve: bool,
        request: Request,
        body: SingleDecision | None = None,
    ) -> JSONResponse:
        audited = False

        def audit_first(approval: Approval, new_status: Status) -> None:
            nonlocal audited
            self._audit_human_decision(approval, new_status)
            audited = True

        try:
            status = self.approvals.decide(
                approval_id,
                approve,
                before_commit=audit_first,
                expected_hash=body.action_hash if body is not None else None,
                require_hash=True,
            )
        except DecideError as exc:
            code = 404 if exc.not_found else 422 if exc.hash_required else 409
            reason = (
                "approval not found"
                if exc.not_found
                else HASH_REQUIRED
                if exc.hash_required
                else "arguments not available yet (Warden restarted): approve after the "
                "agent asks again"
                if exc.no_arguments
                else "action_hash doesn't match this approval (list the approvals again)"
                if exc.hash_mismatch
                else "approval already decided"
            )
            self._record_event_safely(
                AuditEvent.now(
                    EventKind.APPROVAL_DECIDE_FAILED,
                    reason,
                    http_status=code,
                    method=request.method,
                    path=request.url.path,
                    # Only keep the id if it looks like a real one.
                    approval_id=approval_id
                    if re.fullmatch(APPROVAL_ID_PATTERN, approval_id)
                    else None,
                )
            )
            return JSONResponse(status_code=code, content={"error": reason})
        except Exception as exc:
            logger.error("approval not changed, audit or save failed: %s", type(exc).__name__)
            if audited:
                # In the audit log, but saving the approval failed: say so in the log too,
                # so it never claims a decision that didn't take effect.
                self._record_event_safely(
                    AuditEvent.now(
                        EventKind.APPROVAL_DECIDE_FAILED,
                        "decision NOT applied (approval storage failed), nothing changed",
                        http_status=503,
                        method=request.method,
                        path=request.url.path,
                        approval_id=approval_id,  # known: the store found it
                    )
                )
            return JSONResponse(
                status_code=503, content={"error": "audit log unavailable, nothing changed"}
            )
        logger.info("approval %s", status)  # never log the id or arguments
        return JSONResponse(content={"approval_id": approval_id, "status": status.value})

    def lift(self, approval_id: str, request: Request) -> JSONResponse:
        """Lift a rejection, audited BEFORE it takes effect: if the audit write fails,
        the rejection stays. Lifting only lets the agent ask again; what it asks for is
        an ordinary pending approval that a human must approve after seeing it."""
        audited = False

        def audit_first(approval: Approval) -> None:
            nonlocal audited
            self.audit_log.record_event(
                AuditEvent.now(
                    EventKind.APPROVAL_REJECTION_LIFTED,
                    "rejection lifted by admin",
                    approval_id=approval.approval_id,
                    agent_id=approval.agent_id,
                    tool=approval.tool,
                    action_hash=approval.action_hash,
                )
            )
            audited = True

        try:
            self.approvals.lift(approval_id, before_commit=audit_first)
        except DecideError as exc:
            code = 404 if exc.not_found else 409
            reason = "rejection not found" if exc.not_found else "not a rejection (nothing to lift)"
            self._record_event_safely(
                AuditEvent.now(
                    EventKind.APPROVAL_DECIDE_FAILED,
                    reason,
                    http_status=code,
                    method=request.method,
                    path=request.url.path,
                    approval_id=approval_id
                    if re.fullmatch(APPROVAL_ID_PATTERN, approval_id)
                    else None,
                )
            )
            return JSONResponse(status_code=code, content={"error": reason})
        except Exception as exc:
            logger.error("rejection not lifted, audit or save failed: %s", type(exc).__name__)
            if audited:
                self._record_event_safely(
                    AuditEvent.now(
                        EventKind.APPROVAL_DECIDE_FAILED,
                        "lift NOT applied (approval storage failed), the rejection stands",
                        http_status=503,
                        method=request.method,
                        path=request.url.path,
                        approval_id=approval_id,  # known: the store found it
                    )
                )
            return JSONResponse(
                status_code=503, content={"error": "audit log unavailable, nothing changed"}
            )
        logger.info("rejection lifted")  # never log the id or arguments
        return JSONResponse(content={"approval_id": approval_id, "status": "lifted"})

    def _audit_human_decision(self, approval: Approval, new_status: Status) -> None:
        """Runs BEFORE the approval changes. If this write fails, decide() raises and
        the approval stays pending: no human decision goes unrecorded."""
        self.audit_log.record_event(_decision_event(approval, new_status))

    def decide_group(self, body: GroupDecision, request: Request) -> JSONResponse:
        """Approve or deny several approvals of one agent and tool, all or nothing."""
        if body.action_hashes is None:  # approving AND rejecting need what was shown
            if self._within_rejection_limit():  # a flood of bad calls can't fill the disk
                self._emit(
                    AuditEvent.now(
                        EventKind.APPROVAL_DECIDE_FAILED,
                        f"group decision refused: {HASHES_REQUIRED}",
                        http_status=422,
                        method=request.method,
                        path=request.url.path,
                    )
                )
            return JSONResponse(status_code=422, content={"error": HASHES_REQUIRED})
        audited = False

        def audit_first(approvals: list[Approval], new_status: Status) -> None:
            nonlocal audited
            self._audit_group_decision(approvals, new_status)
            audited = True

        try:
            decided = self.approvals.decide_group(
                body.ids,
                body.approve,
                before_commit=audit_first,
                expected_hashes=body.action_hashes,
            )
        except GroupDecideError as exc:
            if self._within_rejection_limit():  # a flood of bad calls can't fill the disk
                self._emit(
                    AuditEvent.now(
                        EventKind.APPROVAL_DECIDE_FAILED,
                        f"group decision refused: {len(exc.failed)} of {len(body.ids)} ids "
                        "failed, nothing changed",
                        http_status=409,
                        method=request.method,
                        path=request.url.path,
                    )
                )
            return JSONResponse(
                status_code=409,
                content={
                    "error": "nothing changed: some approvals can't be decided",
                    # Ids matched APPROVAL_ID_PATTERN, so echoing them is safe.
                    "failed": [{"id": i, "reason": reason.value} for i, reason in exc.failed],
                },
            )
        except Exception as exc:
            logger.error("group not changed, audit or save failed: %s", type(exc).__name__)
            if audited:
                # The decision is in the audit log, but saving it failed: say so in the
                # log too, so the log never claims a decision that didn't take effect.
                self._record_event_safely(
                    AuditEvent.now(
                        EventKind.APPROVAL_DECIDE_FAILED,
                        "group decision NOT applied (approval storage failed), nothing "
                        f"changed: {' '.join(body.ids)}",
                        http_status=503,
                        method=request.method,
                        path=request.url.path,
                    )
                )
            return JSONResponse(
                status_code=503, content={"error": "audit log unavailable, nothing changed"}
            )
        status = Status.APPROVED if body.approve else Status.DENIED
        logger.info("group of %d approvals %s", len(decided), status)
        return JSONResponse(
            content={
                "status": status.value,
                "count": len(decided),
                "results": [
                    {"approval_id": a.approval_id, "status": a.status.value} for a in decided
                ],
            }
        )

    def _audit_group_decision(self, approvals: list[Approval], new_status: Status) -> None:
        """One event for the group, one per approval (as for single decisions), in one
        transaction, BEFORE anything changes. If it fails, nothing changes."""
        first = approvals[0]  # a group shares one agent and tool
        verb = "approved" if new_status is Status.APPROVED else "rejected"
        ids = " ".join(a.approval_id for a in approvals)
        group = AuditEvent.now(
            EventKind.APPROVAL_GROUP_DECIDED,
            f"group of {len(approvals)} {verb} by admin: {ids}",
            agent_id=first.agent_id,
            tool=first.tool,
        )
        audit.record_events(
            self.audit_log, [group, *(_decision_event(a, new_status) for a in approvals)]
        )


def _age(a: Approval, seconds_left: float) -> float:
    """Seconds since the agent asked. `seconds_left` = expires_at - now (both on the
    store's clock), so now = expires_at - seconds_left. Never negative."""
    return max(0.0, a.expires_at - seconds_left - a.created_at)


def _approval_item(a: Approval, seconds_left: float) -> dict[str, JsonValue]:
    """One pending approval as shown to the human."""
    warnings: list[str] = []
    if a.arguments is None:
        shown: JsonValue = None
        warnings.append(
            "arguments not available (Warden restarted); they appear when the agent "
            "asks again. Approving is blocked until then."
        )
    else:
        shown = _display_safe(a.arguments, warnings)
    return {
        "approval_id": a.approval_id,
        "agent_id": a.agent_id,
        "tool": a.tool,
        # The human must see what they approve, and see it HONESTLY: hidden
        # characters are shown escaped (see _display_safe).
        "arguments": shown,
        "warnings": [w for w in sorted(set(warnings))],
        "action_hash": a.action_hash,
        "expires_in_seconds": int(seconds_left),
        "age_seconds": int(_age(a, seconds_left)),
    }


def _rejection_item(a: Approval, seconds_left: float, since: float) -> dict[str, JsonValue]:
    """One standing rejection. No arguments: they are never kept for rejections."""
    rejected_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - since))
    return {
        "approval_id": a.approval_id,
        "agent_id": a.agent_id,
        "tool": a.tool,
        "action_hash": a.action_hash,
        "rejected_at": rejected_at,
        "expires_in_seconds": int(seconds_left),
    }


def _decision_event(approval: Approval, new_status: Status) -> AuditEvent:
    """The audit event for one human decision. approval.status is still the OLD one."""
    kind = (
        EventKind.APPROVAL_APPROVED if new_status is Status.APPROVED else EventKind.APPROVAL_DENIED
    )
    revoked = approval.status is Status.APPROVED
    return AuditEvent.now(
        kind,
        "approval revoked by admin" if revoked else f"approval {new_status.value} by admin",
        approval_id=approval.approval_id,
        agent_id=approval.agent_id,
        tool=approval.tool,
        action_hash=approval.action_hash,
    )


def create_app(
    policy_path: Path = DEFAULT_POLICY_PATH,
    audit_log: AuditLog | None = None,
    approvals: ApprovalStore | None = None,
    admin_key: str | None = None,
    agents: AgentRegistry | None = None,
) -> FastAPI:
    """Build the app. Rules, audit log, approvals and admin key are set up once, here.

    Raises StartupError if the policy has per-agent rules but agent ids can't be
    trusted (no agents file), or names an agent that isn't in the agents file.
    """
    policy = load_policy(policy_path)
    problem = per_agent_problem(policy, agents.agent_ids if agents is not None else None)
    if problem is not None:
        raise StartupError(problem)
    if admin_key is None:
        # New random key every start. Printed to the terminal (for the human),
        # never written to the log file and never sent to agents.
        admin_key = secrets.token_urlsafe(32)
        print(f"\nWarden admin key (needed to approve actions): {admin_key}\n", file=sys.stderr)
    w = _Warden(
        policy=policy,
        audit_log=audit_log or SQLiteAuditLog(audit.DEFAULT_AUDIT_PATH),
        approvals=approvals or ApprovalStore(),
        admin_key=admin_key,
        agents=agents,
        record_in_background=RECORD_REJECTIONS_IN_BACKGROUND,
    )

    # No redirects: "/v1/evaluate/" is a plain 404 deny, not an empty 307.
    app = FastAPI(title="Warden", version=__version__, redirect_slashes=False)
    app.state.warden = w  # for tests and debugging
    # Middleware runs in reverse order of adding: HostCheck, then BodySizeLimit, then
    # DuplicateKeyCheck (which may read the body, so it must come after the size limit).
    app.add_middleware(DuplicateKeyCheck, on_reject=w.record_rejection)
    app.add_middleware(BodySizeLimit, on_reject=w.record_rejection)
    # Added after those, so it runs before them: refuse foreign Host headers first.
    app.add_middleware(HostCheck, allowed=ALLOWED_HOSTS, on_reject=w.record_rejection)
    # Around everything: a crash anywhere becomes a 500 deny. Not an exception handler
    # for Exception: Starlette re-raises after calling it, and Uvicorn then logs the full
    # traceback with the exception's message, which may hold tool arguments.
    app.add_middleware(CrashGuard, on_reject=w.record_rejection)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the input back, which may contain secrets.
        return w.reject(request, 422, "invalid request")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # e.g. 404 unknown URL, 405 wrong method: answer with a deny body like every
        # other error, and record it (repeated 404s can mean someone is probing).
        reasons = {404: "not found", 405: "method not allowed"}
        return w.reject(request, exc.status_code, reasons.get(exc.status_code, "refused"))

    @app.exception_handler(_AdminKeyError)
    async def bad_admin_key(request: Request, exc: _AdminKeyError) -> JSONResponse:
        return w.reject(request, 401, "admin key missing or wrong")

    @app.exception_handler(_RateLimited)
    async def rate_limited(request: Request, exc: _RateLimited) -> JSONResponse:
        response = w.reject(request, 429, "rate limit exceeded")
        response.headers["Retry-After"] = str(max(1, math.ceil(exc.retry_after)))
        return response

    @app.exception_handler(_AgentTokenError)
    async def bad_agent_token(request: Request, exc: _AgentTokenError) -> JSONResponse:
        return w.reject(request, exc.status, exc.reason)

    admin = [Depends(w.require_admin)]
    app.get("/health")(w.health)
    app.post("/v1/evaluate", response_model=EvaluationResult)(w.evaluate)
    app.get("/v1/approvals", dependencies=admin, response_model=None)(w.list_approvals)
    app.post("/v1/approvals/decide", dependencies=admin)(w.decide_group)

    @app.post("/v1/approvals/{approval_id}/approve", dependencies=admin)
    def approve(
        approval_id: str, request: Request, body: SingleDecision | None = None
    ) -> JSONResponse:
        return w.decide(approval_id, approve=True, request=request, body=body)

    @app.post("/v1/approvals/{approval_id}/deny", dependencies=admin)
    def deny(
        approval_id: str, request: Request, body: SingleDecision | None = None
    ) -> JSONResponse:
        return w.decide(approval_id, approve=False, request=request, body=body)

    @app.post("/v1/approvals/{approval_id}/lift", dependencies=admin)
    def lift(approval_id: str, request: Request) -> JSONResponse:
        return w.lift(approval_id, request=request)

    return app


def log_config() -> dict[str, Any]:
    """Uvicorn's logging setup, plus Warden's own loggers at INFO.

    Without this, Warden's log lines (decisions, policy errors) are not shown.
    They go through the same handler and format as Uvicorn's own lines.
    """
    config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    config["loggers"]["warden"] = {
        "handlers": ["default"],
        "level": "INFO",
        "propagate": False,  # mutation-ok: True would only print lines twice
    }
    return config


def main(settings: Settings | None = None) -> None:
    """Start the server on this machine only."""
    settings = settings or Settings()
    config = log_config()
    # Configure logging BEFORE building the app, so policy-file errors are shown.
    logging.config.dictConfig(config)
    try:
        audit_log = SQLiteAuditLog(settings.audit_db, retention_days=settings.retention_days)
        # Approval state lives in the same private database file (never arguments).
        approvals = ApprovalStore(db=ApprovalDB(settings.audit_db))
    except (sqlite3.Error, OSError, ValueError) as exc:
        # e.g. a corrupted file, or a folder Warden can't write to. Without an audit
        # log nothing could ever be allowed, so stop with a clear message.
        raise StartupError(f"can't open the audit database {settings.audit_db}: {exc}") from exc
    agents = None
    if settings.agents is not None:
        try:
            agents = load_agents(settings.agents)
        except AgentsError as exc:
            raise StartupError(str(exc)) from exc
        print(f"\nWarden: {len(agents.agent_ids)} agents with tokens\n", file=sys.stderr)
    else:
        print(
            "\nWarden: no agent tokens (--agents): any local program can claim any agent_id\n",
            file=sys.stderr,
        )
    if settings.admin_key is not None:
        print("\nWarden admin key: using WARDEN_ADMIN_KEY\n", file=sys.stderr)
    app = create_app(
        policy_path=settings.policy,
        audit_log=audit_log,
        approvals=approvals,
        admin_key=settings.admin_key,
        agents=agents,
    )
    uvicorn.run(app, host=HOST, port=settings.port, log_config=config)
