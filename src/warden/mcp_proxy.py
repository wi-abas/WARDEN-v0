"""`warden proxy`: an MCP (Model Context Protocol) stdio proxy that asks Warden first.

The MCP client (Claude Desktop, Cursor, Claude Code, ...) launches this proxy instead of
the real MCP server. The proxy launches the real server as a child process and relays
newline-delimited JSON-RPC messages both ways. Every `tools/call` is checked with Warden:

- allow            -> forwarded to the server (the exact object that was checked)
- deny             -> a tool error goes back to the client; the server never sees it
- require_approval -> wait for a human (mode "wait"), or answer "pending" (mode "error")
- Warden down      -> deny

Other client requests pass only if their method is on the pass-through list. Messages
with repeated JSON keys, JSON-RPC batches and invalid JSON are refused, never forwarded.

Server -> client: responses and notifications pass. Requests (sampling, roots,
elicitation, ...) are answered by the proxy with an error unless the config's
"allow_server_requests" lists them; malformed messages are dropped.
See docs/design/mcp-proxy.md and docs/design/proxy-hardening.md for the threat model.

stdout is the MCP channel, so everything human-readable goes to stderr.
"""

import asyncio
import json
import logging
import os
import re
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, BinaryIO, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, field_validator

from warden.client import DEFAULT_URL, Answer, WardenClient, check_url
from warden.models import AGENT_ID_PATTERN, Decision
from warden.policy import DuplicateKeyError, describe_errors, no_duplicate_keys

logger = logging.getLogger(__name__)

MAX_LINE_BYTES = 16 * 1024 * 1024  # one JSON-RPC message
MAX_IN_FLIGHT = 64  # tool calls being checked (or waiting for approval) at once
SHUTDOWN_GRACE_SECONDS = 5.0  # how long the server gets to exit after the client leaves
MAX_ANSWER_BACKLOG = 1024 * 1024  # unsent bytes before the proxy's own answers are dropped

# Requests that carry no tool side effects of their own and are needed for the protocol.
# Anything else (resources/read, prompts/get, completion/complete, ...) must be listed in
# the config's "allow_methods" to pass. tools/call is always checked, never passed.
PASS_THROUGH = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "logging/setLevel",
    }
)

# The only top-level keys of a client request or notification (exact, case-sensitive).
# Anything else is refused: a server that ignores case could read "Method" as "method"
# and run something Warden never checked.
REQUEST_KEYS = frozenset({"jsonrpc", "id", "method", "params"})

# The fields a tools/call may carry; anything else is refused. "_meta" is protocol
# metadata (e.g. a progress token): only keys on the config's "allow_meta_keys" list,
# holding short text or a whole number, may be in it (see _meta_problem).
TOOL_CALL_PARAMS = frozenset({"name", "arguments", "_meta"})
DEFAULT_META_KEYS = ("progressToken",)
META_KEY_PATTERN = r"^[A-Za-z][A-Za-z0-9._/-]{0,63}$"  # ASCII only: no look-alikes
MAX_META_TEXT = 256
MAX_META_INT = 2**53 - 1  # the largest whole number every JSON parser reads exactly

# Requests the server may send the client, e.g. "roots/list". None by default.
SERVER_METHOD_PATTERN = r"^[a-z][A-Za-z0-9_]*(/[a-z][A-Za-z0-9_]*)*$"
# Client capabilities removed from "initialize" unless the matching request is allowed,
# so well-behaved servers don't try (the requests are refused either way).
CAPABILITY_METHODS = {
    "sampling": "sampling/createMessage",
    "elicitation": "elicitation/create",
    "roots": "roots/list",
}

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


# Warden's own secrets. The proxy's environment holds them (the agent token for asking
# Warden; the admin key if the user exported it for `warden approvals`), but the MCP
# server must never get them: with the admin key it could approve its own calls.
WARDEN_SECRETS = frozenset({"WARDEN_ADMIN_KEY", "WARDEN_AGENT_TOKEN"})


def server_env(spec_env: dict[str, str], inherited: dict[str, str]) -> dict[str, str]:
    """The MCP server's environment: ours minus Warden's secrets, plus the config's
    "env" (set there on purpose, so it is kept as written)."""
    return {**{k: v for k, v in inherited.items() if k not in WARDEN_SECRETS}, **spec_env}


class ConfigError(ValueError):
    """The proxy configuration is invalid. The message never contains secret values."""


class ServerSpec(BaseModel):
    """How to start the real MCP server."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,  # mutation-ok: no JSON value is coerced into these text fields anyway
        frozen=True,
    )

    command: str = Field(min_length=1)
    args: tuple[str, ...] = ()
    # Extra environment variables for the server (e.g. its API key). Never logged.
    env: dict[str, str] = Field(default_factory=dict)


class ApprovalSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    # "wait": hold the call until a human decides (or timeout). "error": answer at once
    # with a "pending approval" tool error; the agent retries later.
    mode: Literal["wait", "error"] = "wait"
    timeout_seconds: float = Field(default=300, gt=0, le=3600)
    poll_seconds: float = Field(default=2, ge=0.01, le=60)


class ProxyConfig(BaseModel):
    """The proxy's config file. Unknown keys are refused (a typo must not be ignored)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    warden_url: str = DEFAULT_URL
    agent_id: str = Field(default="mcp-proxy", pattern=AGENT_ID_PATTERN)
    # Put in front of every tool name sent to Warden, e.g. "github." so that rules can
    # tell two servers' "search" tools apart. Same characters as tool names.
    tool_prefix: str = Field(default="", pattern=r"^[a-z0-9_.\-]{0,32}$")
    server: ServerSpec
    approval: ApprovalSettings = ApprovalSettings()
    allow_methods: tuple[str, ...] = ()
    # Keys a tools/call's "_meta" may hold. Anything else refuses the whole call.
    allow_meta_keys: tuple[Annotated[str, Field(pattern=META_KEY_PATTERN)], ...] = DEFAULT_META_KEYS
    # Requests the server may send the client (sampling, roots, elicitation, ...).
    # Anything not listed is answered by the proxy with an error, never forwarded.
    allow_server_requests: tuple[
        Annotated[str, Field(pattern=SERVER_METHOD_PATTERN, max_length=64)], ...
    ] = ()
    warden_timeout_seconds: float = Field(default=5, gt=0, le=60)

    @field_validator("warden_url")
    @classmethod
    def url_is_local(cls, value: str) -> str:
        return check_url(value)

    @field_validator("allow_methods")
    @classmethod
    def tools_call_stays_checked(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # Nor a look-alike (other case, spaces) that a sloppy server takes for tools/call.
        if any(method.strip().casefold() == "tools/call" for method in value):
            raise ValueError("tools/call is always checked by Warden; it can't be allowed")
        return value


def load_config(path: Path) -> ProxyConfig:
    try:
        raw = path.read_text(encoding="utf-8")
        json.loads(raw, object_pairs_hook=no_duplicate_keys)
        return ProxyConfig.model_validate_json(raw)
    except DuplicateKeyError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    except ValidationError as exc:
        raise ConfigError(f"{path}: {'; '.join(describe_errors(exc))}") from None
    except (OSError, ValueError, RecursionError) as exc:
        raise ConfigError(f"{path}: can't read it ({type(exc).__name__})") from None


class Checker(Protocol):
    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer: ...


class _Refused(Exception):
    """A client message that must not be forwarded."""

    def __init__(self, code: int, message: str, *, duplicate_key: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.duplicate_key = duplicate_key


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")  # NaN / Infinity


def parse_message(line: bytes) -> Any:
    """Strict JSON: no repeated keys (parsers disagree on which copy wins), no NaN, and
    nothing that can't be re-encoded (a lone "\\ud800" escape would crash `encode`).
    Plain UTF-8 only: json.loads(bytes) would quietly accept a byte order mark or
    UTF-16/32, so the bytes are decoded first (a BOM is then refused as invalid JSON)."""
    try:
        message = json.loads(
            line.decode("utf-8"), object_pairs_hook=no_duplicate_keys, parse_constant=_no_constants
        )
    except DuplicateKeyError:
        raise _Refused(
            INVALID_REQUEST, "repeated key in message (refused by Warden)", duplicate_key=True
        ) from None
    except ValueError:
        raise _Refused(PARSE_ERROR, "invalid JSON") from None
    except RecursionError:  # e.g. 100,000 nested "[": would crash the relay
        raise _Refused(INVALID_REQUEST, "message nested too deeply (refused by Warden)") from None
    try:
        encode(message)
    except UnicodeEncodeError:
        raise _Refused(INVALID_REQUEST, "invalid text in message (refused by Warden)") from None
    except RecursionError:
        raise _Refused(INVALID_REQUEST, "message nested too deeply (refused by Warden)") from None
    return message


def recover_id(line: bytes) -> JsonValue:
    """The id of a message refused for a repeated key, so the client's request gets its
    error answer instead of hanging. Only when it is unambiguous: the top level has
    exactly one "id", and it is a valid id. Otherwise None (an answer with id null)."""
    try:
        top = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=lambda pairs: pairs,
            parse_constant=_no_constants,
        )
    except (ValueError, RecursionError):
        return None
    # A top-level object comes back as a list of (key, value) TUPLES. JSON arrays are
    # lists, never tuples, so a batch or any other shape finds no "id" here.
    if not isinstance(top, list):
        return None
    ids = [pair[1] for pair in top if isinstance(pair, tuple) and pair[0] == "id"]
    if len(ids) != 1:
        return None
    found = ids[0]
    if not (found is None or isinstance(found, str) or type(found) is int):  # _valid_id
        return None
    try:
        encode(found)
    except UnicodeEncodeError:  # a lone surrogate can't be sent back
        return None
    return found


def encode(message: Any) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def _safe_name(text: object) -> str:
    """For log lines: no control characters, bounded length (names come from the agent)."""
    return ascii(str(text)[:64])


def _method_for_log(method: str) -> str:
    """A server's method name for a log line, only if it looks like a method name (so a
    hostile server can't put data in our logs)."""
    if len(method) <= 64 and re.fullmatch(SERVER_METHOD_PATTERN, method):
        return _safe_name(method)
    return "(unusual name)"


def tool_error(request_id: JsonValue, text: str) -> dict[str, JsonValue]:
    """A tool result marked as an error: the model sees the text and can adapt."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def rpc_error(request_id: JsonValue, code: int, message: str) -> dict[str, JsonValue]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class McpProxy:
    """Relays one client <-> server session. All I/O is injected, so tests can drive it."""

    def __init__(
        self,
        config: ProxyConfig,
        checker: Checker,
        read_client: Callable[[], Awaitable[bytes | None]],
        write_client: Callable[[bytes], None],
    ) -> None:
        self.config = config
        self.checker = checker
        self.read_client = read_client
        self.write_client = write_client
        self.allowed_methods = PASS_THROUGH | set(config.allow_methods)
        self.allowed_server_requests = frozenset(config.allow_server_requests)
        self._calls: dict[str, asyncio.Task[None]] = {}  # in-flight tool calls by id
        self._held: set[str] = set()  # ids of tool calls not (yet) sent to the server
        self._backlog_warned = False
        self._server_in: asyncio.StreamWriter | None = None

    # --- Session ----------------------------------------------------------------------

    async def run(self) -> int:
        """Start the server, relay until either side ends. Returns the server's exit code."""
        spec = self.config.server
        process = await asyncio.create_subprocess_exec(
            spec.command,
            *spec.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            env=server_env(spec.env, dict(os.environ)),
            limit=MAX_LINE_BYTES,
        )
        # mutation-ok: both are set (PIPE); the assert only informs the type checker
        assert process.stdin is not None and process.stdout is not None  # noqa: S101 (PIPE)
        self._server_in = process.stdin
        server_side = asyncio.create_task(self._relay_server(process.stdout))
        client_side = asyncio.create_task(self._relay_client())
        await asyncio.wait({server_side, client_side}, return_when=asyncio.FIRST_COMPLETED)
        # mutation-ok: `or` differs only if both sides end at the very same moment
        if client_side.done() and not server_side.done():
            # The client closed its input. Calls already accepted still get their answer
            # (each one ends: Warden has a timeout, approvals have a deadline).
            # mutation-ok: calls never raise (they answer errors themselves)
            await asyncio.gather(*self._calls.values(), return_exceptions=True)
        else:
            client_side.cancel()
        for call in list(self._calls.values()):
            call.cancel()
        # Let the server finish what it's writing, then stop it if it doesn't exit.
        process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=SHUTDOWN_GRACE_SECONDS)
        except TimeoutError:
            process.kill()
            await process.wait()
        await asyncio.wait({server_side}, timeout=SHUTDOWN_GRACE_SECONDS)
        server_side.cancel()
        # mutation-ok: after wait() there always is a return code
        return process.returncode if process.returncode is not None else 1

    async def _relay_server(self, stdout: asyncio.StreamReader) -> None:
        while True:
            try:
                line = await stdout.readline()
            except ValueError:  # a line over MAX_LINE_BYTES
                logger.error("MCP server sent a message over %d bytes; stopping", MAX_LINE_BYTES)
                return
            if not line:
                return
            if line.strip():
                await self._handle_server(line)

    async def _handle_server(self, line: bytes) -> None:
        """Server -> client. Responses and notifications pass (the server is the tool
        itself and is trusted for what it says). Requests pass only if allowed: a server
        must not get an LLM call, the user's file roots or the user's input unchecked.
        Whatever passes is re-encoded from the parsed object, like client -> server."""
        try:
            message = parse_message(line)
        except _Refused as refused:
            logger.warning("dropped a message from the MCP server (%s)", refused.message)
            return
        kind = _server_message_kind(message)
        if kind is None:
            logger.warning("dropped a malformed message from the MCP server")
        elif kind == "response" and json.dumps(message["id"]) in self._held:
            # The proxy hasn't sent that call yet (still checking or waiting for a
            # human): the server can't have answered it.
            logger.warning("dropped a server response to a call Warden hasn't forwarded")
        elif kind != "request" or message["method"] in self.allowed_server_requests:
            self._reply(message)
        elif message["method"] == "ping":
            self._answer_server({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            logger.warning(
                "refused server request %s (not in allow_server_requests)",
                _method_for_log(message["method"]),
            )
            self._answer_server(
                rpc_error(message["id"], METHOD_NOT_FOUND, "request refused by Warden proxy")
            )

    async def _relay_client(self) -> None:
        while True:
            line = await self.read_client()
            if line == b"":
                return
            if line is None:
                self._reply(rpc_error(None, INVALID_REQUEST, "message too large"))
                continue
            if not line.strip():
                continue
            await self._handle(line)

    # --- One client message -----------------------------------------------------------

    async def _handle(self, line: bytes) -> None:
        try:
            message = parse_message(line)
            if not isinstance(message, dict):
                raise _Refused(INVALID_REQUEST, "batches and non-object messages not supported")
        except _Refused as refused:
            request_id = recover_id(line) if refused.duplicate_key else None
            self._reply(rpc_error(request_id, refused.code, refused.message))
            return

        has_id = "id" in message
        request_id = message.get("id")
        if message.get("jsonrpc") != "2.0" or not _valid_id(request_id):
            if has_id or "method" in message:
                self._reply(rpc_error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message"))
            return
        method = message.get("method")

        if "method" not in message:
            # Only a well-formed response (to a request the server sent) is forwarded:
            # {"jsonrpc", "id", and exactly one of "result" / "error"}. Anything else
            # (e.g. "params" without a method) could be read as a call by a sloppy server.
            if has_id and _is_response(message):
                await self._forward(message)
            elif has_id:
                self._reply(rpc_error(None, INVALID_REQUEST, "not a valid response"))
            return
        if not isinstance(method, str):
            self._reply(rpc_error(None, INVALID_REQUEST, "method must be text"))
            return
        if not set(message) <= REQUEST_KEYS:
            logger.warning("refused a message from the client (unexpected key)")
            if has_id:
                self._reply(rpc_error(request_id, INVALID_REQUEST, "unexpected key in message"))
            return
        if not has_id:  # a notification: no answer expected
            if method == "notifications/cancelled":
                self._cancel(message.get("params"))
            if method.startswith("notifications/"):
                await self._forward(message)
            else:
                # e.g. "tools/call" without an id: a server might still run it.
                logger.warning("dropped notification %s (not allowed)", _safe_name(method))
            return
        if method == "tools/call":
            self._start_call(request_id, message)
        elif method == "initialize":
            await self._forward(
                _without_refused_capabilities(message, self.allowed_server_requests)
            )
        elif method in self.allowed_methods:
            await self._forward(message)
        else:
            logger.warning("refused method %s (not on the allow list)", _safe_name(method))
            self._reply(
                rpc_error(request_id, METHOD_NOT_FOUND, "method not allowed by Warden proxy")
            )

    def _start_call(self, request_id: JsonValue, message: dict[str, Any]) -> None:
        key = json.dumps(request_id)
        if len(self._calls) >= MAX_IN_FLIGHT:
            self._reply(tool_error(request_id, "Blocked by Warden: too many calls in progress"))
            return
        if key in self._calls:
            self._reply(rpc_error(request_id, INVALID_REQUEST, "request id already in use"))
            return
        task = asyncio.create_task(self._tool_call(request_id, message))
        self._calls[key] = task
        self._held.add(key)

        def done(_: object) -> None:
            self._calls.pop(key, None)
            self._held.discard(key)

        task.add_done_callback(done)

    def _cancel(self, params: object) -> None:
        """The client gave up on a request: stop waiting for its approval."""
        if isinstance(params, dict) and _valid_id(params.get("requestId")):
            task = self._calls.get(json.dumps(params.get("requestId")))
            if task is not None:
                task.cancel()

    async def _tool_call(self, request_id: JsonValue, message: dict[str, Any]) -> None:
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            self._reply(rpc_error(request_id, INVALID_PARAMS, "tools/call needs a tool name"))
            return
        if not set(params) <= TOOL_CALL_PARAMS:
            # A server might read an extra field (e.g. "argumentsOverride") that Warden
            # never checked. Refuse instead of forwarding it.
            self._reply(rpc_error(request_id, INVALID_PARAMS, "unexpected field in tools/call"))
            return
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            self._reply(rpc_error(request_id, INVALID_PARAMS, "arguments must be an object"))
            return
        if "_meta" in params:
            problem = _meta_problem(params["_meta"], self.config.allow_meta_keys)
            if problem is not None:
                # Refuse the whole call: never forward a partly cleaned message.
                logger.warning("refused tools/call: _meta %s", problem)
                self._reply(rpc_error(request_id, INVALID_PARAMS, f"_meta {problem}"))
                return
        name: str = params["name"]
        try:
            answer = await self._decide(self.config.tool_prefix + name, arguments)
        except Exception as exc:  # fail closed, whatever went wrong
            logger.error("check failed: %s", type(exc).__name__)
            answer = Answer(Decision.DENY, "check failed")
        logger.info("tools/call %s -> %s", _safe_name(name), answer.decision.value)
        if answer.allowed:
            # Forward the SAME parsed object Warden checked, re-encoded: never the raw
            # bytes, so the server can't read anything Warden didn't see.
            self._held.discard(json.dumps(request_id))
            await self._forward(message)
        else:
            self._reply(tool_error(request_id, f"Blocked by Warden: {answer.reason}"))

    async def _ask(self, tool: str, arguments: dict[str, Any], approval_id: str | None) -> Answer:
        return await asyncio.to_thread(self.checker.evaluate, tool, arguments, approval_id)

    async def _decide(self, tool: str, arguments: dict[str, Any]) -> Answer:
        answer = await self._ask(tool, arguments, None)
        if answer.decision is not Decision.REQUIRE_APPROVAL:
            return answer
        approval_id = answer.approval_id
        if approval_id is None:
            return Answer(Decision.DENY, "approval needed, but Warden gave no approval id")
        # Maybe a human already approved this exact action (Warden reuses the id).
        answer = await self._ask(tool, arguments, approval_id)
        settings = self.config.approval
        if answer.decision is Decision.REQUIRE_APPROVAL:
            url = f"--warden-url {self.config.warden_url}"
            # Review first: Warden refuses an approval without the action_hash from the
            # list. `warden approvals approve` lists, shows and sends it; the hint never
            # prints the hash itself (the human must get it from the list).
            print(
                f"Warden: {_safe_name(tool)} needs approval (id {approval_id}).\n"
                "  1. Check what it would do:  warden approvals list "
                f"--agent {self.config.agent_id} {url}\n"
                f"  2. Then approve it:         warden approvals approve {approval_id} {url}\n"
                "  (both need WARDEN_ADMIN_KEY; with curl, see docs/mcp-proxy.md)",
                file=sys.stderr,
            )
        if settings.mode == "error" and answer.decision is Decision.REQUIRE_APPROVAL:
            return Answer(
                Decision.DENY,
                f"waiting for a human to approve (approval id {approval_id}). "
                "Retry the same call after approval.",
            )
        deadline = time.monotonic() + settings.timeout_seconds
        # Rate limited (429) while polling: back off and keep waiting, never allow.
        while answer.decision is Decision.REQUIRE_APPROVAL or answer.retry_after is not None:
            if time.monotonic() >= deadline:  # mutation-ok: equal floats never happen
                return Answer(Decision.DENY, "timed out waiting for a human to approve")
            await asyncio.sleep(max(settings.poll_seconds, answer.retry_after or 0.0))
            answer = await self._ask(tool, arguments, approval_id)
        return answer

    # --- Output -----------------------------------------------------------------------

    def _reply(self, message: dict[str, JsonValue]) -> None:
        self.write_client(encode(message))

    def _answer_server(self, message: dict[str, JsonValue]) -> None:
        """The proxy's own answer to a server request. Never waits: a server that floods
        requests without reading its input must not stall the relay. Past
        MAX_ANSWER_BACKLOG unsent bytes, answers are dropped (still never forwarded)."""
        writer = self._server_in
        if writer is None or writer.is_closing():
            return
        if writer.transport.get_write_buffer_size() > MAX_ANSWER_BACKLOG:
            if not self._backlog_warned:
                logger.warning("MCP server isn't reading its input; dropping answers to it")
                self._backlog_warned = True
            return
        try:
            writer.write(encode(message))
        except (ConnectionError, RuntimeError):
            logger.error("MCP server is no longer reading its input")

    async def _forward(self, message: dict[str, Any]) -> None:
        writer = self._server_in
        if writer is None or writer.is_closing():
            return
        try:
            writer.write(encode(message))
            await writer.drain()
        except (ConnectionError, RuntimeError):
            logger.error("MCP server is no longer reading its input")


def _meta_problem(meta: object, allowed_keys: tuple[str, ...]) -> str | None:
    """Why a tools/call's "_meta" can't be forwarded, or None if it can.

    The answer never contains the keys or values themselves (they come from the agent)."""
    if not isinstance(meta, dict):
        return "must be an object"
    for key, value in meta.items():
        if key not in allowed_keys:
            return "has a key that isn't allowed"
        if type(value) is int:
            if abs(value) > MAX_META_INT:
                return "has a number that is too large"
        elif isinstance(value, str):
            if not 0 < len(value) <= MAX_META_TEXT or not (value.isascii() and value.isprintable()):
                return f"text must be 1-{MAX_META_TEXT} printable ASCII characters"
        else:
            return "values must be text or whole numbers"
    return None


def _server_message_kind(message: object) -> Literal["response", "notification", "request"] | None:
    """Exactly one JSON-RPC shape, or None. Strict, so that a request can't pass as a
    response or notification (e.g. a message with both "method" and "result")."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return None
    if "method" not in message:
        return "response" if _is_response(message) and _valid_id(message["id"]) else None
    if not isinstance(message["method"], str) or not isinstance(message.get("params", {}), dict):
        return None
    keys = set(message)
    if keys <= {"jsonrpc", "method", "params"}:
        # Like client -> server: only "notifications/..." (a sloppy client might act on a
        # "sampling/createMessage" without an id).
        return "notification" if message["method"].startswith("notifications/") else None
    if keys <= {"jsonrpc", "id", "method", "params"} and message["id"] is not None:
        return "request" if _valid_id(message["id"]) else None
    return None


def _without_refused_capabilities(message: dict[str, Any], allowed: frozenset[str]) -> Any:
    """The client's initialize, minus capabilities for server requests the proxy refuses."""
    params = message.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("capabilities"), dict):
        return message
    capabilities = {
        name: value
        for name, value in params["capabilities"].items()
        if name not in CAPABILITY_METHODS or CAPABILITY_METHODS[name] in allowed
    }
    return {**message, "params": {**params, "capabilities": capabilities}}


def _is_response(message: dict[str, Any]) -> bool:
    keys = set(message)
    return keys in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})


def _valid_id(value: object) -> bool:
    """JSON-RPC ids are text, whole numbers or null (absent counts as valid)."""
    return value is None or isinstance(value, str) or (type(value) is int)


# --- Real stdin / stdout -------------------------------------------------------------


def read_line(stream: BinaryIO, limit: int = MAX_LINE_BYTES) -> bytes | None:
    """One line, b"" at end of input, None if the line was longer than `limit`
    (the rest of it is skipped)."""
    line = stream.readline(limit + 1)
    if len(line) > limit and not line.endswith(b"\n"):
        while True:
            rest = stream.readline(limit)
            if not rest or rest.endswith(b"\n"):
                return None
    return line


def stdin_reader(
    loop: asyncio.AbstractEventLoop, stream: BinaryIO
) -> Callable[[], Awaitable[bytes | None]]:
    """Read `stream` in a daemon thread (works on every OS, never blocks shutdown)."""
    queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=64)  # mutation-ok: tuning

    def worker() -> None:
        while True:
            line = read_line(stream)
            put = queue.put(line)
            try:
                asyncio.run_coroutine_threadsafe(put, loop).result()
            except RuntimeError:  # the loop is gone: we're shutting down
                put.close()
                return
            if line == b"":
                return

    # mutation-ok: daemon only matters at interpreter exit
    threading.Thread(target=worker, name="warden-proxy-stdin", daemon=True).start()
    return queue.get


def stdout_writer(stream: BinaryIO) -> Callable[[bytes], None]:
    def write(data: bytes) -> None:
        stream.write(data)
        stream.flush()

    return write


def serve_stdio(config: ProxyConfig) -> int:
    """Run the proxy on this process's stdin/stdout. Returns the server's exit code."""
    # The agent token comes from the environment (e.g. the MCP client config's "env"),
    # never from the config file, so it isn't stored next to the server settings.
    checker = WardenClient(
        config.warden_url,
        config.agent_id,
        timeout=config.warden_timeout_seconds,
        token=os.environ.get("WARDEN_AGENT_TOKEN") or None,
    )

    async def main() -> int:
        loop = asyncio.get_running_loop()
        proxy = McpProxy(
            config, checker, stdin_reader(loop, sys.stdin.buffer), stdout_writer(sys.stdout.buffer)
        )
        return await proxy.run()

    return asyncio.run(main())
