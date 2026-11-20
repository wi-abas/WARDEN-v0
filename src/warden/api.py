"""The HTTP API that agents talk to. A thin layer: no security logic lives here.

Endpoints:
- GET  /health       -> is the server up, and how many rules loaded (0 = broken policy file)
- POST /v1/evaluate  -> send an ActionRequest, get an EvaluationResult

Every error response still carries "decision": "deny", so a careless client
that only reads the decision field fails closed.

Run it with `uv run warden` (listens on 127.0.0.1 only: this machine, not the network).
"""

import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

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


def create_app(policy_path: Path = DEFAULT_POLICY_PATH) -> FastAPI:
    """Build the app. Rules are loaded once, here, at startup."""
    rules = load_rules(policy_path)

    app = FastAPI(title="Warden", version="0.1.0")
    app.add_middleware(BodySizeLimit)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the input back, which may contain secrets.
        return _deny_response(422, "invalid request")

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Log only the error type; never the message or a stack trace with arguments.
        logger.error("unexpected error handling request: %s", type(exc).__name__)
        return _deny_response(500, "internal error")

    @app.get("/health")
    def health() -> dict[str, str | int]:
        return {"status": "ok", "rules_loaded": len(rules)}

    @app.post("/v1/evaluate")
    def evaluate_action(action: ActionRequest) -> EvaluationResult:
        result = evaluate(action, rules)
        # Safe to log: tool names and rule ids are pattern-checked. Never log arguments.
        logger.info(
            "decision=%s tool=%s rule=%s", result.decision, action.tool, result.matched_rule
        )
        return result

    return app


def main() -> None:
    """Start the server on this machine only."""
    uvicorn.run("warden.api:create_app", factory=True, host=HOST, port=PORT)
