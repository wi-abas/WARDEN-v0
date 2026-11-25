"""A small client for asking a local Warden server about one tool call.

Used by the MCP proxy (`warden proxy`) and the Python SDK (`warden.sdk`). Standard
library only.

Fail closed: anything other than a well-formed answer from Warden (unreachable, timeout,
HTTP error, garbage, an unknown decision) becomes DENY. The caller runs the tool only
when `Answer.allowed` is True.

The URL must point at this machine (127.0.0.1, localhost or ::1): Warden only listens
locally, and tool arguments may contain secrets that must never go anywhere else.
"""

import http.client
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from pydantic import JsonValue

from warden.models import APPROVAL_ID_PATTERN, Decision

DEFAULT_URL = "http://127.0.0.1:8000"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_RESPONSE_BYTES = 64 * 1024
# Warden refuses bodies over this (api.MAX_BODY_BYTES; a test keeps them equal). Checked
# here first: the server refuses before reading, so sending it anyway usually ends in a
# reset connection, which would look like "Warden unreachable".
MAX_REQUEST_BYTES = 64 * 1024


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would follow it to any host and send the agent
    token or admin key along. Returning None makes urllib raise HTTPError (a deny)."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# Never through a proxy: urllib follows HTTP_PROXY / http_proxy even for 127.0.0.1, which
# would send tool arguments (and the admin key, for `warden approvals`) to the proxy and
# make us trust ITS answer. An empty ProxyHandler turns proxies off for this opener.
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())


def open_local(request: urllib.request.Request, timeout: float) -> Any:
    """urlopen() for Warden's own local URL: no proxies, no redirects."""
    return _LOCAL_OPENER.open(request, timeout=timeout)


class ClientConfigError(ValueError):
    """The client was set up wrongly (e.g. a URL that isn't on this machine)."""


@dataclass(frozen=True)
class Answer:
    """Warden's answer, reduced to what a caller needs."""

    decision: Decision
    reason: str
    approval_id: str | None = None
    action_hash: str | None = None
    # Set when Warden said "too many requests" (HTTP 429): seconds to wait before
    # asking again. Always a deny; only polling loops use it to keep waiting.
    retry_after: float | None = None
    # Set when no answer came back (connection refused or lost, timeout: e.g. Warden is
    # restarting). Always a deny; only a wait for a human may ask again.
    unreachable: bool = field(default=False, compare=False)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


def _deny(reason: str) -> Answer:
    return Answer(decision=Decision.DENY, reason=reason)


def check_url(url: str) -> str:
    """Return `url` without a trailing "/", or raise if it isn't a local http:// URL."""
    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError on a bad port
    except ValueError:
        raise ClientConfigError("Warden URL is not valid") from None
    if parts.scheme != "http" or parts.hostname not in LOCAL_HOSTS:
        raise ClientConfigError(
            "Warden URL must be http://127.0.0.1:<port> or http://localhost:<port> "
            "(Warden only runs on this machine)"
        )
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ClientConfigError("Warden URL must not contain a user, query or fragment")
    if parts.path not in {"", "/"} or port is None:
        raise ClientConfigError("Warden URL must be just scheme, host and port")
    return url.rstrip("/")


def parse_answer(data: Any) -> Answer:
    """Validate Warden's JSON answer. Anything unexpected is a deny."""
    if not isinstance(data, dict):
        return _deny("unexpected answer from Warden")
    raw_decision = data.get("decision")
    if raw_decision not in {d.value for d in Decision}:
        return _deny("unexpected answer from Warden")
    decision = Decision(raw_decision)
    reason = data.get("reason")
    reason = reason[:200] if isinstance(reason, str) else "no reason given"
    approval_id = data.get("approval_id")
    if not (isinstance(approval_id, str) and re.fullmatch(APPROVAL_ID_PATTERN, approval_id)):
        approval_id = None
    action_hash = data.get("action_hash")
    if not (isinstance(action_hash, str) and re.fullmatch(r"[0-9a-f]{64}", action_hash)):
        action_hash = None
    return Answer(decision, reason, approval_id, action_hash)


class WardenClient:
    """Asks a local Warden server for decisions. Never raises from `evaluate`.

    With a `token`, the agent id comes from the token. If you also give an `agent_id`, it
    is sent too, and Warden denies everything (HTTP 403) if the token belongs to another
    agent: a mix-up is a clear "no" instead of acting as the wrong agent."""

    def __init__(
        self,
        url: str = DEFAULT_URL,
        agent_id: str | None = None,
        *,
        timeout: float = 5.0,
        token: str | None = None,
    ) -> None:
        self.url = check_url(url)
        # Agent token (warden agent add). Warden takes the agent id from it, so without
        # an explicit agent_id none is sent.
        self._token = token
        self.agent_id = "agent" if agent_id is None and token is None else agent_id
        self.timeout = timeout

    def __repr__(self) -> str:  # never show the token
        token = "<set>" if self._token else None
        agent = "<from token>" if self.agent_id is None else repr(self.agent_id)
        return f"WardenClient(url={self.url!r}, agent_id={agent}, token={token})"

    def evaluate(
        self,
        tool: str,
        arguments: dict[str, JsonValue],
        approval_id: str | None = None,
    ) -> Answer:
        """Ask about one tool call. Any failure is a DENY answer, never an exception."""
        try:
            return self._evaluate(tool, arguments, approval_id)
        except (OSError, http.client.HTTPException):
            return Answer(Decision.DENY, "Warden unreachable", unreachable=True)
        except Exception:
            # Don't include the error text: it could quote the arguments.
            return _deny("Warden unreachable")

    def _evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None
    ) -> Answer:
        body: dict[str, JsonValue] = {"tool": tool, "arguments": arguments}
        headers = {"content-type": "application/json"}
        if self.agent_id is not None:
            body["agent_id"] = self.agent_id
        if self._token is not None:
            headers["authorization"] = f"Bearer {self._token}"
        if approval_id is not None:
            body["approval_id"] = approval_id
        data = json.dumps(body, allow_nan=False).encode("utf-8")
        if len(data) > MAX_REQUEST_BYTES:
            return _deny(f"request too large for Warden (limit {MAX_REQUEST_BYTES // 1024} KB)")
        request = urllib.request.Request(  # noqa: S310 (check_url: local http only)
            f"{self.url}/v1/evaluate",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with open_local(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            # Warden's error bodies say "deny" too; keep its reason if it gave one.
            with error:
                answer = parse_answer(_json_or_none(error.read(MAX_RESPONSE_BYTES + 1)))
            if answer.allowed:  # an error status is never an allow
                return _deny(f"Warden returned HTTP {error.code}")
            if error.code == 429:
                return Answer(Decision.DENY, "rate limit exceeded", retry_after=_retry_after(error))
            return answer if answer.reason != "no reason given" else _deny(f"HTTP {error.code}")
        if len(raw) > MAX_RESPONSE_BYTES:
            return _deny("answer from Warden too large")
        return parse_answer(_json_or_none(raw))


def capped_pause(pause: float, left: float, total: float) -> float:
    """How long to pause before asking again about an approval, with `left` of `total`
    seconds to go. Cut short for one last question a moment before the deadline (so its
    answer can arrive in time); after that one, just the rest of the wait."""
    margin = min(0.25, total / 10)
    return left if left < margin * 1.5 else min(pause, left - margin)


def _retry_after(error: urllib.error.HTTPError) -> float:
    """Retry-After in seconds, kept between 1 and 60 (garbage or missing: 1)."""
    raw = (error.headers.get("Retry-After") or "").strip()
    seconds = int(raw) if raw.isascii() and raw.isdigit() and len(raw) < 6 else 1
    return float(min(max(seconds, 1), 60))


def _json_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None
