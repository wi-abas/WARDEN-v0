"""Python SDK: run a tool only if Warden says allow, with exactly what Warden checked.

    from warden.sdk import WardenClient, guard

    warden = WardenClient(agent_id="billing-agent")

    @guard(client=warden, wait_for_approval=120)
    def send_invoice(to: str, amount: int) -> str: ...

Anything but allow raises NotAllowed and the function does not run. The arguments are
frozen (bound to parameter names, defaults applied, copied through JSON) BEFORE the
check, and the function receives that frozen copy: changing the caller's objects after
the check has no effect. See docs/design/sdk.md.
"""

import asyncio
import functools
import inspect
import json
import os
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

from pydantic import JsonValue

from warden.client import DEFAULT_URL, Answer, WardenClient
from warden.models import TOOL_NAME_PATTERN, Decision

__all__ = [
    "ApprovalPending",
    "NotAllowed",
    "WardenClient",
    "default_client",
    "freeze",
    "guard",
    "run_guarded",
    "run_guarded_async",
]


class NotAllowed(Exception):
    """Warden didn't say allow, so the tool did not run. `answer` says why."""

    def __init__(self, answer: Answer) -> None:
        super().__init__(answer.reason)
        self.answer = answer


class ApprovalPending(NotAllowed):
    """A human must approve first. Retry the same call later (same arguments)."""

    @property
    def approval_id(self) -> str | None:
        return self.answer.approval_id


def default_client() -> WardenClient:
    """A client from WARDEN_URL, WARDEN_AGENT_ID and WARDEN_AGENT_TOKEN
    (defaults: local Warden, "agent", no token)."""
    return WardenClient(
        os.environ.get("WARDEN_URL", DEFAULT_URL),
        os.environ.get("WARDEN_AGENT_ID", "agent"),
        token=os.environ.get("WARDEN_AGENT_TOKEN") or None,
    )


def freeze(arguments: dict[str, Any]) -> dict[str, JsonValue] | None:
    """A deep, JSON-only copy of `arguments`, or None if they aren't plain JSON values.

    This one copy is both checked and executed. JSON is the format Warden checks, so a
    value with no exact JSON form (an object, a set, NaN) can't be checked at all.
    """
    try:
        copy = json.loads(json.dumps(arguments, allow_nan=False))
    except (TypeError, ValueError):
        return None
    return cast(dict[str, JsonValue], copy)


def _refused(reason: str) -> NotAllowed:
    return NotAllowed(Answer(Decision.DENY, reason))


def _final(answer: Answer) -> None:
    """Raise unless the answer is allow."""
    if answer.allowed:
        return
    if answer.decision is Decision.REQUIRE_APPROVAL:
        raise ApprovalPending(answer)
    raise NotAllowed(answer)


def _decide(
    client: WardenClient,
    tool: str,
    arguments: dict[str, JsonValue],
    wait_for_approval: float,
    poll_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
) -> Answer:
    answer = client.evaluate(tool, arguments)
    if answer.decision is not Decision.REQUIRE_APPROVAL:
        return answer
    approval_id = answer.approval_id
    if approval_id is None:
        return Answer(Decision.DENY, "approval needed, but Warden gave no approval id")
    deadline = time.monotonic() + wait_for_approval
    # The first re-ask is immediate: a human may already have approved this exact action.
    answer = client.evaluate(tool, arguments, approval_id)
    while answer.decision is Decision.REQUIRE_APPROVAL and time.monotonic() < deadline:
        sleep(poll_seconds)
        answer = client.evaluate(tool, arguments, approval_id)
    return answer


def run_guarded[R](
    tool: str,
    arguments: dict[str, Any],
    fn: Callable[..., R],
    *,
    client: WardenClient | None = None,
    wait_for_approval: float = 0,
    poll_seconds: float = 2.0,
) -> R:
    """Check `tool` with `arguments`; on allow, return fn(**frozen copy). Else raise."""
    frozen = freeze(arguments)
    if frozen is None:
        raise _refused("arguments are not plain JSON values, so they can't be checked")
    client = client or default_client()
    _final(_decide(client, tool, frozen, wait_for_approval, poll_seconds))
    return fn(**frozen)


async def run_guarded_async[R](
    tool: str,
    arguments: dict[str, Any],
    fn: Callable[..., Awaitable[R]],
    *,
    client: WardenClient | None = None,
    wait_for_approval: float = 0,
    poll_seconds: float = 2.0,
) -> R:
    """Like run_guarded, for `async def` tools. Never blocks the event loop."""
    frozen = freeze(arguments)
    if frozen is None:
        raise _refused("arguments are not plain JSON values, so they can't be checked")
    client = client or default_client()
    answer = await asyncio.to_thread(_decide, client, tool, frozen, wait_for_approval, poll_seconds)
    _final(answer)
    return await fn(**frozen)


def _check_signature(fn: Callable[..., Any]) -> inspect.Signature:
    signature = inspect.signature(fn)
    for param in signature.parameters.values():
        if param.kind in {param.POSITIONAL_ONLY, param.VAR_POSITIONAL}:
            raise TypeError(
                f"@guard can't name parameter {param.name!r} of {fn.__name__}() for the "
                "policy: use normal or keyword parameters"
            )
    return signature


def _named_arguments(
    signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Every argument by name, defaults included; **kwargs merged in at the top level."""
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    named: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        if signature.parameters[name].kind is inspect.Parameter.VAR_KEYWORD:
            named.update(value)
        else:
            named[name] = value
    return named


def guard[**P, R](
    tool: str | None = None,
    *,
    client: WardenClient | None = None,
    wait_for_approval: float = 0,
    poll_seconds: float = 2.0,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator: the function runs only on allow, with the frozen, checked arguments.

    `tool` defaults to the function's name. `client` defaults to default_client() at
    call time. `wait_for_approval`: seconds to wait for a human (0 = raise
    ApprovalPending at once; call again with the same arguments after approving).
    """

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        name = tool or fn.__name__
        if not re.fullmatch(TOOL_NAME_PATTERN, name):
            raise ValueError(f"tool name {name!r} isn't valid for Warden ({TOOL_NAME_PATTERN})")
        signature = _check_signature(fn)
        options: dict[str, Any] = {
            "client": client,
            "wait_for_approval": wait_for_approval,
            "poll_seconds": poll_seconds,
        }

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                named = _named_arguments(signature, args, kwargs)
                return await run_guarded_async(name, named, fn, **options)

            return cast(Callable[P, R], async_wrapper)

        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            named = _named_arguments(signature, args, kwargs)
            return run_guarded(name, named, fn, **options)

        return wrapper

    return decorate
