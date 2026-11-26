"""A small client for asking a local Warden server about one tool call.

Used by the MCP proxy (`warden proxy`) and the Python SDK (`warden.sdk`). Standard
library only.

Fail closed: anything other than a well-formed answer from Warden (unreachable, timeout,
HTTP error, garbage, an unknown decision) becomes DENY. The caller runs the tool only
when `Answer.allowed` is True.

With an agent token, Warden must prove that it is Warden before the token or any
argument is sent, and its answer must be signed (see docs/design/server-identity.md).
Nothing turns that off. Without a token there is no shared secret, so nothing is proven.

The URL must point at this machine (127.0.0.1, localhost or ::1): Warden only listens
locally, and tool arguments may contain secrets that must never go anywhere else.
"""

import hashlib
import http.client
import json
import re
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from pydantic import JsonValue

from warden import identity
from warden.models import APPROVAL_ID_PATTERN, Decision

DEFAULT_URL = "http://127.0.0.1:8000"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_RESPONSE_BYTES = 64 * 1024
# Warden refuses bodies over this (api.MAX_BODY_BYTES; a test keeps them equal). Checked
# here first: the server refuses before reading, so sending it anyway usually ends in a
# reset connection, which would look like "Warden unreachable".
MAX_REQUEST_BYTES = 64 * 1024
MAX_HELLO_BYTES = 4096
NOT_PROVEN = "Warden couldn't prove its identity"


NO_AUTH_VAR = "WARDEN_NO_AUTH"
NO_AUTH_HELP = (
    "create a token with `warden agent add NAME` and set WARDEN_AGENT_TOKEN, or set "
    "WARDEN_NO_AUTH=1 to run without agent tokens on purpose (any local program can then "
    "claim any agent id, and nothing proves who answers)"
)


def no_auth_from_env(env: Mapping[str, str]) -> bool:
    """True if WARDEN_NO_AUTH is exactly "1". Any other non-empty value is a mistake
    ("true", "0", "yes"): refused, so a value meant as "off" never quietly means on."""
    value = env.get(NO_AUTH_VAR, "")
    if value not in ("", "1"):
        raise ValueError(f"{NO_AUTH_VAR} must be 1 or unset")
    return value == "1"


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


class NotProven(Exception):
    """Whatever answered didn't prove that it is Warden. The message holds no secrets."""

    def __init__(self, why: str = "", *, unknown_key: bool = False) -> None:
        super().__init__(f"{NOT_PROVEN} ({why})" if why else NOT_PROVEN)
        self.unknown_key = unknown_key  # it says it doesn't know our secret


class ProofTimeout(NotProven):
    """No proof in time."""


class AnswerTooLarge(Exception):
    """The answer is over the caller's limit, so it was not read to its end."""


@dataclass(frozen=True)  # mutation-ok: nothing assigns to it
class Reply:
    """An HTTP answer. From `ask_proven`: its MAC was right."""

    status: int
    body: bytes
    headers: Any  # http.client.HTTPMessage


class _DeadlineSocket(socket.socket):
    """A socket whose reads and writes must ALL be done by `deadline`. An ordinary timeout
    starts again with every byte, so an impostor could keep a client waiting for ever."""

    deadline: float

    def _limit(self) -> None:
        left = self.deadline - time.monotonic()
        if left <= 0:  # mutation-ok: equal floats never happen
            raise TimeoutError("timed out")
        self.settimeout(left)

    def recv_into(self, *args: Any, **kwargs: Any) -> int:
        self._limit()
        return super().recv_into(*args, **kwargs)

    def sendall(self, *args: Any, **kwargs: Any) -> None:
        self._limit()
        super().sendall(*args, **kwargs)


class _OneConnection(http.client.HTTPConnection):
    """Never reconnects by itself: what was proven is this one connection. Doesn't follow
    redirects and ignores proxy settings, as http.client always does."""

    auto_open = 0

    def __init__(self, host: str, port: int, deadline: float) -> None:
        super().__init__(host, port, timeout=max(0.001, deadline - time.monotonic()))
        self.deadline = deadline

    def connect(self) -> None:
        super().connect()
        sock = _DeadlineSocket(fileno=self.sock.detach())
        sock.deadline = self.deadline
        self.sock = sock


def ask_proven(
    url: str,
    key: bytes,
    method: str,
    path: str,
    body: bytes | None,
    headers: dict[str, str],
    *,
    timeout: float,
    limit: int,
) -> Reply:
    """One question to Warden, which must prove `key` first (`url`: from check_url).
    `headers` (with the secret) and `body` are only sent after that, and the answer only
    counts with a valid MAC. `timeout` is for everything together.

    Raises NotProven, AnswerTooLarge, or OSError / http.client.HTTPException if the
    connection was refused or lost."""
    parts = urlsplit(url)
    deadline = time.monotonic() + timeout
    host, port = parts.hostname or "", parts.port or 0  # mutation-ok: check_url wants both
    connection = _OneConnection(host, port, deadline)
    try:
        try:
            connection.connect()
        except TimeoutError:
            raise ProofTimeout("no answer in time") from None
        # The real ends of this connection. An impostor that passes the hello on to Warden
        # needs a connection of its own, and Warden signs the ends of that one.
        server = identity.address(connection.sock.getpeername())
        client = identity.address(connection.sock.getsockname())
        nonce = identity.new_nonce()
        _check_hello(connection, key, nonce, server, client)
        connection.request(method, path, body, {**headers, identity.NONCE_HEADER: nonce})
        response = connection.getresponse()
        raw = response.read(limit + 1)  # mutation-ok: one byte over is enough to tell
        if len(raw) > limit:
            raise AnswerTooLarge
        if response.length:  # closed early: lost, like a refused connection
            raise http.client.IncompleteRead(b"")
        macs = response.headers.get_all(identity.MAC_HEADER) or []
        retry_after = response.headers.get_all("Retry-After") or [""]
        expected = identity.answer_mac(
            key,
            nonce=nonce,
            server=server,
            client=client,
            method=method,
            target=path.encode("ascii"),
            request_sha256=hashlib.sha256(body or b"").hexdigest(),
            status=response.status,
            retry_after=",".join(retry_after).encode("latin-1"),
            body=raw,
        )
        if len(macs) != 1 or not identity.same_mac(expected, macs[0]):
            raise NotProven("its answer isn't signed correctly")
        return Reply(response.status, raw, response.headers)
    finally:
        connection.close()


def _check_hello(
    connection: _OneConnection, key: bytes, nonce: str, server: str, client: str
) -> None:
    """Raise unless the other end proves that it has `key`. Sends no secret."""
    hello = json.dumps(
        {
            "key_id": identity.key_id(key),
            "nonce": nonce,
            "client_mac": identity.client_hello_mac(key, nonce, server, client),
        }
    ).encode()
    try:
        connection.request("POST", identity.HELLO_PATH, hello, {"content-type": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_HELLO_BYTES + 1)  # mutation-ok: one over is enough to tell
    except TimeoutError:
        raise ProofTimeout("no answer in time") from None
    except OSError:
        raise  # refused or lost: e.g. Warden is restarting
    except Exception:  # not HTTP
        raise NotProven from None
    if response.status == 401:
        raise NotProven("wrong or removed secret, or it isn't Warden", unknown_key=True)
    answer = _json_or_none(raw)
    if (
        response.status != 200
        or len(raw) > MAX_HELLO_BYTES
        or not isinstance(answer, dict)
        or not identity.same_mac(identity.hello_mac(key, nonce, server, client), answer.get("mac"))
    ):
        raise NotProven


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
    agent: a mix-up is a clear "no" instead of acting as the wrong agent.

    With a `token`, Warden must prove its identity before anything secret is sent.
    `timeout` then covers the proof and the question together."""

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
        self._key = None if token is None else identity.proof_key(token)
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
        except NotProven as exc:
            return _deny(str(exc))  # never `unreachable`: not asked again
        except AnswerTooLarge:
            return _deny("answer from Warden too large")
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
        if self._key is not None:
            reply = ask_proven(
                self.url,
                self._key,
                "POST",
                "/v1/evaluate",
                data,
                headers,
                timeout=self.timeout,
                limit=MAX_RESPONSE_BYTES,
            )
            return _read_answer(reply)
        request = urllib.request.Request(  # noqa: S310 (check_url: local http only)
            f"{self.url}/v1/evaluate",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with open_local(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                return _read_answer(Reply(response.status, raw, response.headers))
        except urllib.error.HTTPError as error:
            with error:
                raw = error.read(MAX_RESPONSE_BYTES + 1)
                return _read_answer(Reply(error.code, raw, error.headers))


def _read_answer(reply: Reply) -> Answer:
    if not 200 <= reply.status < 300:
        # Warden's error bodies say "deny" too; keep its reason if it gave one.
        answer = parse_answer(_json_or_none(reply.body))
        if answer.allowed:  # an error status is never an allow
            return _deny(f"Warden returned HTTP {reply.status}")
        if reply.status == 429:
            return Answer(Decision.DENY, "rate limit exceeded", retry_after=_retry_after(reply))
        return answer if answer.reason != "no reason given" else _deny(f"HTTP {reply.status}")
    if len(reply.body) > MAX_RESPONSE_BYTES:
        return _deny("answer from Warden too large")
    return parse_answer(_json_or_none(reply.body))


def capped_pause(pause: float, left: float, total: float) -> float:
    """How long to pause before asking again about an approval, with `left` of `total`
    seconds to go. Cut short for one last question a moment before the deadline (so its
    answer can arrive in time); after that one, just the rest of the wait."""
    margin = min(0.25, total / 10)
    return left if left < margin * 1.5 else min(pause, left - margin)


def _retry_after(reply: Reply) -> float:
    """Retry-After in seconds, kept between 1 and 60 (garbage or missing: 1)."""
    raw = (reply.headers.get("Retry-After") or "").strip()
    seconds = int(raw) if raw.isascii() and raw.isdigit() and len(raw) < 6 else 1
    return float(min(max(seconds, 1), 60))


def _json_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return None
