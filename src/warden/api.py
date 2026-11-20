"""The HTTP API that agents talk to. A thin layer: no security logic lives here.

Endpoints:
- GET  /health       -> is the server up, and how many rules loaded (0 = broken policy file)
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

import logging
import secrets
import sys
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import JsonValue
from starlette.types import ASGIApp, Receive, Scope, Send

from warden import audit
from warden.approvals import ApprovalStore, DecideError, apply_approval
from warden.audit import AuditEntry, AuditLog, SQLiteAuditLog
from warden.engine import evaluate
from warden.models import ActionRequest, Decision, EvaluationResult
from warden.policy import DEFAULT_POLICY_PATH, load_rules

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 8000
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

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            length = headers.get(b"content-length")
            if length is None and b"transfer-encoding" in headers:
                await _deny_response(411, "content-length required")(scope, receive, send)
                return
            if length is not None and (not length.isdigit() or int(length) > self.max_bytes):
                await _deny_response(413, "request too large")(scope, receive, send)
                return
        await self.app(scope, receive, send)


class _AdminKeyError(Exception):
    pass


def create_app(
    policy_path: Path = DEFAULT_POLICY_PATH,
    audit_log: AuditLog | None = None,
    approvals: ApprovalStore | None = None,
    admin_key: str | None = None,
) -> FastAPI:
    """Build the app. Rules, audit log, approvals and admin key are set up once, here."""
    rules = load_rules(policy_path)
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

    app = FastAPI(title="Warden", version="0.1.0")
    app.add_middleware(BodySizeLimit)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the input back, which may contain secrets.
        return _deny_response(422, "invalid request")

    @app.exception_handler(_AdminKeyError)
    async def bad_admin_key(request: Request, exc: _AdminKeyError) -> JSONResponse:
        return _deny_response(401, "admin key missing or wrong")

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Log only the error type; never the message or a stack trace with arguments.
        logger.error("unexpected error handling request: %s", type(exc).__name__)
        return _deny_response(500, "internal error")

    @app.get("/health")
    def health() -> dict[str, str | int]:
        return {"status": "ok", "rules_loaded": len(rules)}

    @app.post("/v1/evaluate", response_model=EvaluationResult)
    def evaluate_action(action: ActionRequest) -> EvaluationResult | JSONResponse:
        result = apply_approval(action, evaluate(action, rules), approvals)
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

    def _decide(approval_id: str, approve: bool) -> JSONResponse:
        try:
            status = approvals.decide(approval_id, approve)
        except DecideError as exc:
            if exc.not_found:
                return JSONResponse(status_code=404, content={"error": "approval not found"})
            return JSONResponse(status_code=409, content={"error": "approval already decided"})
        logger.info("approval %s", status)  # never log the id or arguments
        return JSONResponse(content={"approval_id": approval_id, "status": status.value})

    @app.post("/v1/approvals/{approval_id}/approve", dependencies=[Depends(require_admin)])
    def approve(approval_id: str) -> JSONResponse:
        return _decide(approval_id, approve=True)

    @app.post("/v1/approvals/{approval_id}/deny", dependencies=[Depends(require_admin)])
    def deny(approval_id: str) -> JSONResponse:
        return _decide(approval_id, approve=False)

    return app


def main() -> None:
    """Start the server on this machine only."""
    uvicorn.run("warden.api:create_app", factory=True, host=HOST, port=PORT)
