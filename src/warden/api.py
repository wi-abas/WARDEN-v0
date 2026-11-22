"""The HTTP API that agents talk to. A thin layer: no security logic lives here.

Endpoints:
- GET  /health       -> "ok", or "degraded" (HTTP 503) when no rules loaded: everything is denied
- POST /v1/evaluate  -> send an ActionRequest, get an EvaluationResult

Admin only (header "X-Warden-Admin-Key", printed in the terminal at startup):
- GET  /v1/approvals                  -> pending approvals, with their arguments
- POST /v1/approvals/{id}/approve     -> approve one (once)
- POST /v1/approvals/{id}/deny        -> deny one (once)

Every decision is written to the audit log before it is returned. If the
audit log can't be written, the answer is deny (503): no unrecorded allows.

Every error response still carries "decision": "deny", so a careless client
that only reads the decision field fails closed.

Run it with `uv run warden` (listens on 127.0.0.1 only: this machine, not the network).
"""

import copy
import logging
import logging.config
import re
import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
import uvicorn.config
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import JsonValue
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

from warden import __version__, audit
from warden.approvals import Approval, ApprovalStore, DecideError, Status, apply_approval
from warden.audit import AuditEntry, AuditEvent, AuditLog, EventKind, SQLiteAuditLog
from warden.engine import evaluate
from warden.models import APPROVAL_ID_PATTERN, ActionRequest, Decision, EvaluationResult
from warden.policy import DEFAULT_POLICY_PATH, Policy, load_policy
from warden.settings import Settings

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
MAX_BODY_BYTES = 64 * 1024  # 64 KB is far more than any real tool call needs


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


# Host names a request may be addressed to. Anything else is refused, which stops
# "DNS rebinding": a malicious web page pointing its own domain at 127.0.0.1 to
# talk to Warden from your browser.
ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")


def _host_name(raw: bytes) -> str:
    """'127.0.0.1:8000' -> '127.0.0.1', '[::1]:8000' -> '::1'."""
    host = raw.decode("latin-1").strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else ""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


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
            host = dict(scope["headers"]).get(b"host", b"")
            if _host_name(host) not in self.allowed:
                self.on_reject(scope, 400, "host not allowed")
                await _deny_response(400, "host not allowed")(scope, receive, send)
                return
        await self.app(scope, receive, send)


class _AdminKeyError(Exception):
    pass


@dataclass
class _Warden:
    """Everything the routes need, with one method per job. Routes stay one-liners."""

    policy: Policy
    audit_log: AuditLog
    approvals: ApprovalStore
    admin_key: str

    # --- Access control and rejected requests ------------------------------------------

    def require_admin(self, x_warden_admin_key: str | None = Header(default=None)) -> None:
        if x_warden_admin_key is None or not secrets.compare_digest(
            x_warden_admin_key.encode(), self.admin_key.encode()
        ):
            raise _AdminKeyError

    def record_rejection(self, scope: Scope, status: int, reason: str) -> None:
        """Audit a refused request: method and URL path only, never the body."""
        self._record_event_safely(
            AuditEvent.now(
                EventKind.REQUEST_REJECTED,
                reason,
                http_status=status,
                method=str(scope.get("method", "")),
                path=str(scope.get("path", "")),
            )
        )

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

    def evaluate(self, action: ActionRequest) -> EvaluationResult | JSONResponse:
        decision = evaluate(action, self.policy.rules, self.policy.tools)
        result = apply_approval(action, decision, self.approvals)
        try:
            self.audit_log.record(AuditEntry.from_decision(action, result))
        except Exception as exc:
            logger.error("audit log write failed, denying: %s", type(exc).__name__)
            return _deny_response(503, "audit log unavailable")
        # Safe to log: tool names and rule ids are pattern-checked. Never log arguments.
        logger.info(
            "decision=%s tool=%s rule=%s", result.decision, action.tool, result.matched_rule
        )
        return result

    # --- Humans (admin) ----------------------------------------------------------------

    def list_approvals(self) -> list[dict[str, JsonValue]]:
        return [
            {
                "approval_id": a.approval_id,
                "agent_id": a.agent_id,
                "tool": a.tool,
                "arguments": a.arguments,  # the human must see what they approve
                "action_hash": a.action_hash,
                "expires_in_seconds": int(seconds_left),
            }
            for a, seconds_left in self.approvals.pending()
        ]

    def decide(self, approval_id: str, approve: bool, request: Request) -> JSONResponse:
        try:
            status = self.approvals.decide(
                approval_id, approve, before_commit=self._audit_human_decision
            )
        except DecideError as exc:
            code = 404 if exc.not_found else 409
            reason = "approval not found" if exc.not_found else "approval already decided"
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
            logger.error("approval not changed, audit failed: %s", type(exc).__name__)
            return JSONResponse(
                status_code=503, content={"error": "audit log unavailable, nothing changed"}
            )
        logger.info("approval %s", status)  # never log the id or arguments
        return JSONResponse(content={"approval_id": approval_id, "status": status.value})

    def _audit_human_decision(self, approval: Approval, new_status: Status) -> None:
        """Runs BEFORE the approval changes. If this write fails, decide() raises and
        the approval stays pending: no human decision goes unrecorded."""
        kind = (
            EventKind.APPROVAL_APPROVED
            if new_status is Status.APPROVED
            else EventKind.APPROVAL_DENIED
        )
        # approval.status is still the OLD status here.
        revoked = approval.status is Status.APPROVED
        self.audit_log.record_event(
            AuditEvent.now(
                kind,
                "approval revoked by admin" if revoked else f"approval {new_status.value} by admin",
                approval_id=approval.approval_id,
                agent_id=approval.agent_id,
                tool=approval.tool,
                action_hash=approval.action_hash,
            )
        )


def create_app(
    policy_path: Path = DEFAULT_POLICY_PATH,
    audit_log: AuditLog | None = None,
    approvals: ApprovalStore | None = None,
    admin_key: str | None = None,
) -> FastAPI:
    """Build the app. Rules, audit log, approvals and admin key are set up once, here."""
    if admin_key is None:
        # New random key every start. Printed to the terminal (for the human),
        # never written to the log file and never sent to agents.
        admin_key = secrets.token_urlsafe(32)
        print(f"\nWarden admin key (needed to approve actions): {admin_key}\n", file=sys.stderr)
    w = _Warden(
        policy=load_policy(policy_path),
        audit_log=audit_log or SQLiteAuditLog(audit.DEFAULT_AUDIT_PATH),
        approvals=approvals or ApprovalStore(),
        admin_key=admin_key,
    )

    app = FastAPI(title="Warden", version=__version__)
    app.add_middleware(BodySizeLimit, on_reject=w.record_rejection)
    # Added last, so it runs first: refuse foreign Host headers before anything else.
    app.add_middleware(HostCheck, allowed=ALLOWED_HOSTS, on_reject=w.record_rejection)

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

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Log only the error type; never the message or a stack trace with arguments.
        logger.error("unexpected error handling request: %s", type(exc).__name__)
        return w.reject(request, 500, "internal error")

    admin = [Depends(w.require_admin)]
    app.get("/health")(w.health)
    app.post("/v1/evaluate", response_model=EvaluationResult)(w.evaluate)
    app.get("/v1/approvals", dependencies=admin)(w.list_approvals)

    @app.post("/v1/approvals/{approval_id}/approve", dependencies=admin)
    def approve(approval_id: str, request: Request) -> JSONResponse:
        return w.decide(approval_id, approve=True, request=request)

    @app.post("/v1/approvals/{approval_id}/deny", dependencies=admin)
    def deny(approval_id: str, request: Request) -> JSONResponse:
        return w.decide(approval_id, approve=False, request=request)

    return app


def log_config() -> dict[str, Any]:
    """Uvicorn's logging setup, plus Warden's own loggers at INFO.

    Without this, Warden's log lines (decisions, policy errors) are not shown.
    They go through the same handler and format as Uvicorn's own lines.
    """
    config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    config["loggers"]["warden"] = {"handlers": ["default"], "level": "INFO", "propagate": False}
    return config


def main(settings: Settings | None = None) -> None:
    """Start the server on this machine only."""
    settings = settings or Settings()
    config = log_config()
    # Configure logging BEFORE building the app, so policy-file errors are shown.
    logging.config.dictConfig(config)
    if settings.admin_key is not None:
        print("\nWarden admin key: using WARDEN_ADMIN_KEY\n", file=sys.stderr)
    app = create_app(
        policy_path=settings.policy,
        audit_log=SQLiteAuditLog(settings.audit_db, retention_days=settings.retention_days),
        admin_key=settings.admin_key,
    )
    uvicorn.run(app, host=HOST, port=settings.port, log_config=config)
