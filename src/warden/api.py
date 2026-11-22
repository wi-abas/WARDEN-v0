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
from pathlib import Path
from typing import Any

import uvicorn
import uvicorn.config
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import JsonValue
from starlette.types import ASGIApp, Receive, Scope, Send

from warden import audit
from warden.approvals import Approval, ApprovalStore, DecideError, Status, apply_approval
from warden.audit import AuditEntry, AuditEvent, AuditLog, EventKind, SQLiteAuditLog
from warden.engine import evaluate
from warden.models import APPROVAL_ID_PATTERN, ActionRequest, Decision, EvaluationResult
from warden.policy import DEFAULT_POLICY_PATH, load_policy
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


class _AdminKeyError(Exception):
    pass


def create_app(
    policy_path: Path = DEFAULT_POLICY_PATH,
    audit_log: AuditLog | None = None,
    approvals: ApprovalStore | None = None,
    admin_key: str | None = None,
) -> FastAPI:
    """Build the app. Rules, audit log, approvals and admin key are set up once, here."""
    policy = load_policy(policy_path)
    rules = policy.rules
    if audit_log is None:
        audit_log = SQLiteAuditLog(audit.DEFAULT_AUDIT_PATH)
    if approvals is None:
        approvals = ApprovalStore()
    if admin_key is None:
        # New random key every start. Printed to the terminal (for the human),
        # never written to the log file and never sent to agents.
        admin_key = secrets.token_urlsafe(32)
        print(f"\nWarden admin key (needed to approve actions): {admin_key}\n", file=sys.stderr)

    def require_admin(x_warden_admin_key: str | None = Header(default=None)) -> None:
        if x_warden_admin_key is None or not secrets.compare_digest(
            x_warden_admin_key.encode(), admin_key.encode()
        ):
            raise _AdminKeyError

    def record_rejection(scope: Scope, status: int, reason: str) -> None:
        """Audit a refused request: method and URL path only, never the body."""
        try:
            audit_log.record_event(
                AuditEvent.now(
                    EventKind.REQUEST_REJECTED,
                    reason,
                    http_status=status,
                    method=str(scope.get("method", "")),
                    path=str(scope.get("path", "")),
                )
            )
        except Exception as exc:
            # The answer is already deny, so a failed record doesn't change it.
            logger.error("audit event write failed: %s", type(exc).__name__)

    def reject(request: Request, status: int, reason: str) -> JSONResponse:
        record_rejection(request.scope, status, reason)
        return _deny_response(status, reason)

    app = FastAPI(title="Warden", version="0.1.0")
    app.add_middleware(BodySizeLimit, on_reject=record_rejection)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the input back, which may contain secrets.
        return reject(request, 422, "invalid request")

    @app.exception_handler(_AdminKeyError)
    async def bad_admin_key(request: Request, exc: _AdminKeyError) -> JSONResponse:
        return reject(request, 401, "admin key missing or wrong")

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Log only the error type; never the message or a stack trace with arguments.
        logger.error("unexpected error handling request: %s", type(exc).__name__)
        return reject(request, 500, "internal error")

    @app.get("/health")
    def health() -> JSONResponse:
        # No rules means every request is denied: Warden runs, but isn't doing its job.
        # 503 lets monitoring tools notice without reading the body.
        if not rules:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "rules_loaded": 0,
                    "reason": "no rules loaded, every request is denied (check the policy file)",
                },
            )
        return JSONResponse(content={"status": "ok", "rules_loaded": len(rules)})

    @app.post("/v1/evaluate", response_model=EvaluationResult)
    def evaluate_action(action: ActionRequest) -> EvaluationResult | JSONResponse:
        result = apply_approval(action, evaluate(action, rules, policy.tools), approvals)
        try:
            audit_log.record(AuditEntry.from_decision(action, result))
        except Exception as exc:
            logger.error("audit log write failed, denying: %s", type(exc).__name__)
            return _deny_response(503, "audit log unavailable")
        # Safe to log: tool names and rule ids are pattern-checked. Never log arguments.
        logger.info(
            "decision=%s tool=%s rule=%s", result.decision, action.tool, result.matched_rule
        )
        return result

    @app.get("/v1/approvals", dependencies=[Depends(require_admin)])
    def list_approvals() -> list[dict[str, JsonValue]]:
        return [
            {
                "approval_id": a.approval_id,
                "agent_id": a.agent_id,
                "tool": a.tool,
                "arguments": a.arguments,  # the human must see what they approve
                "action_hash": a.action_hash,
                "expires_in_seconds": int(seconds_left),
            }
            for a, seconds_left in approvals.pending()
        ]

    def _decide(approval_id: str, approve: bool, request: Request) -> JSONResponse:
        def audit_first(approval: Approval, new_status: Status) -> None:
            # Runs before the approval changes. If this write fails, decide() raises
            # and the approval stays pending: no human decision goes unrecorded.
            kind = (
                EventKind.APPROVAL_APPROVED
                if new_status is Status.APPROVED
                else EventKind.APPROVAL_DENIED
            )
            audit_log.record_event(
                AuditEvent.now(
                    kind,
                    f"approval {new_status.value} by admin",
                    approval_id=approval.approval_id,
                    agent_id=approval.agent_id,
                    tool=approval.tool,
                    action_hash=approval.action_hash,
                )
            )

        try:
            status = approvals.decide(approval_id, approve, before_commit=audit_first)
        except DecideError as exc:
            reason = "approval not found" if exc.not_found else "approval already decided"
            try:
                audit_log.record_event(
                    AuditEvent.now(
                        EventKind.APPROVAL_DECIDE_FAILED,
                        reason,
                        http_status=404 if exc.not_found else 409,
                        method=request.method,
                        path=request.url.path,
                        # Only keep the id if it looks like a real one.
                        approval_id=approval_id
                        if re.fullmatch(APPROVAL_ID_PATTERN, approval_id)
                        else None,
                    )
                )
            except Exception as audit_exc:
                logger.error("audit event write failed: %s", type(audit_exc).__name__)
            return JSONResponse(
                status_code=404 if exc.not_found else 409, content={"error": reason}
            )
        except Exception as exc:
            logger.error("approval not changed, audit failed: %s", type(exc).__name__)
            return JSONResponse(
                status_code=503, content={"error": "audit log unavailable, nothing changed"}
            )
        logger.info("approval %s", status)  # never log the id or arguments
        return JSONResponse(content={"approval_id": approval_id, "status": status.value})

    @app.post("/v1/approvals/{approval_id}/approve", dependencies=[Depends(require_admin)])
    def approve(approval_id: str, request: Request) -> JSONResponse:
        return _decide(approval_id, approve=True, request=request)

    @app.post("/v1/approvals/{approval_id}/deny", dependencies=[Depends(require_admin)])
    def deny(approval_id: str, request: Request) -> JSONResponse:
        return _decide(approval_id, approve=False, request=request)

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
