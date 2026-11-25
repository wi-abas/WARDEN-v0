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
import dataclasses
import functools
import inspect
import json
import os
import re
import time
from collections.abc import Awaitable, Callable, Generator
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
    (defaults: local Warden, "agent", no token). With a token, the agent id comes from
    the token; if WARDEN_AGENT_ID is set too, it must be the token's agent (else denied)."""
    return WardenClient(
        os.environ.get("WARDEN_URL", DEFAULT_URL),
        os.environ.get("WARDEN_AGENT_ID"),
        token=os.environ.get("WARDEN_AGENT_TOKEN") or None,
    )


def freeze(arguments: dict[str, Any]) -> dict[str, JsonValue] | None:
    """A deep, JSON-only copy of `arguments`, or None if they aren't plain JSON values.

    This one copy is both checked and executed. JSON is the format Warden checks, so a
    value with no exact JSON form (an object, a set, NaN, text with a lone surrogate such
    as "\\ud800") can't be checked at all.
    """
    try:
        text = json.dumps(arguments, allow_nan=False, ensure_ascii=False)
        text.encode("utf-8")  # UnicodeEncodeError (a ValueError) on a lone surrogate
        copy = json.loads(text)
    except (TypeError, ValueError, RecursionError):  # RecursionError: nested too deeply
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


@dataclasses.dataclass(frozen=True)
class _Ask:
    """Step: ask Warden (with this approval id) and send the answer back in."""

    approval_id: str | None = None


@dataclasses.dataclass(frozen=True)
class _Sleep:
    """Step: wait this long."""

    seconds: float


def _steps(
    wait_for_approval: float, poll_seconds: float
) -> Generator[_Ask | _Sleep, Answer | None, Answer]:
    """When to ask and when to wait, without doing either: the sync and the async
    version share this, and differ only in HOW they ask and wait."""
    answer = yield from _ask(None)
    if answer.decision is not Decision.REQUIRE_APPROVAL:
        return answer
    approval_id = answer.approval_id
    if approval_id is None:
        return Answer(Decision.DENY, "approval needed, but Warden gave no approval id")
    why = answer.reason  # the rule's message: why a human must approve
    deadline = time.monotonic() + wait_for_approval
    # The first re-ask is immediate: a human may already have approved this exact action.
    answer = yield from _ask(approval_id)
    while _still_waiting(answer) and time.monotonic() < deadline:
        # Rate limited while polling: back off, keep waiting (it's still not an allow).
        yield _Sleep(max(poll_seconds, answer.retry_after or 0.0))
        answer = yield from _ask(approval_id)
    if answer.decision is Decision.REQUIRE_APPROVAL and answer.reason != why:
        # Re-asks only say "waiting for a human to approve": keep the rule's reason too.
        answer = dataclasses.replace(answer, reason=f"{why} ({answer.reason})")
    return answer


def _ask(approval_id: str | None) -> Generator[_Ask, Answer | None, Answer]:
    answer = yield _Ask(approval_id)
    return answer or Answer(Decision.DENY, "no answer from Warden")


def _decide(
    client: WardenClient,
    tool: str,
    arguments: dict[str, JsonValue],
    wait_for_approval: float,
    poll_seconds: float,
) -> Answer:
    steps = _steps(wait_for_approval, poll_seconds)
    answer: Answer | None = None
    while True:
        try:
            step = steps.send(answer)
        except StopIteration as done:
            return cast(Answer, done.value)
        answer = None
        if isinstance(step, _Ask):
            answer = client.evaluate(tool, arguments, step.approval_id)
        else:
            time.sleep(step.seconds)


async def _decide_async(
    client: WardenClient,
    tool: str,
    arguments: dict[str, JsonValue],
    wait_for_approval: float,
    poll_seconds: float,
) -> Answer:
    """Each question runs in a thread; waiting between them does not, so waiting calls
    don't use up the thread pool, and cancelling stops the questions."""
    steps = _steps(wait_for_approval, poll_seconds)
    answer: Answer | None = None
    while True:
        try:
            step = steps.send(answer)
        except StopIteration as done:
            return cast(Answer, done.value)
        answer = None
        if isinstance(step, _Ask):
            answer = await asyncio.to_thread(client.evaluate, tool, arguments, step.approval_id)
        else:
            await asyncio.sleep(step.seconds)


def _still_waiting(answer: Answer) -> bool:
    """Not decided yet. `unreachable`: Warden may be restarting, and the approval state
    is persisted, so keep asking until the deadline (still never an allow)."""
    return (
        answer.decision is Decision.REQUIRE_APPROVAL
        or answer.retry_after is not None
        or answer.unreachable
    )


def _is_async(fn: Callable[..., Any]) -> bool:
    """True if calling `fn` gives a coroutine (nothing runs until it is awaited): also
    for functools.partial, staticmethod and objects with an `async def __call__`."""
    while isinstance(fn, functools.partial | staticmethod):
        fn = fn.func if isinstance(fn, functools.partial) else fn.__func__
    return inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(
        getattr(type(fn), "__call__", None)  # noqa: B004 (the method, not "is it callable")
    )


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
    if _is_async(fn):
        raise TypeError("run_guarded takes a plain function; use run_guarded_async for async")
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
    """Like run_guarded, for `async def` tools. Never blocks the event loop.

    Cancelling it while it waits stops the polling, so a later approval stays unused. If
    it is cancelled exactly while a question is on its way to Warden, that question may
    still use up the approval although the tool doesn't run: a human must approve again
    (it never runs twice).

    `fn` must be recognisably async: a plain function that returns an awaitable is refused
    with TypeError (wrap it in `async def`, or mark it: inspect.markcoroutinefunction)."""
    if not _is_async(fn):
        raise TypeError("run_guarded_async takes an `async def` function; use run_guarded")
    frozen = freeze(arguments)
    if frozen is None:
        raise _refused("arguments are not plain JSON values, so they can't be checked")
    client = client or default_client()
    _final(await _decide_async(client, tool, frozen, wait_for_approval, poll_seconds))
    return await fn(**frozen)


def _check_signature(fn: Callable[..., Any]) -> inspect.Signature:
    signature = inspect.signature(fn)
    for param in signature.parameters.values():
        if param.kind in {param.POSITIONAL_ONLY, param.VAR_POSITIONAL}:
            raise TypeError(
                f"@guard can't name parameter {param.name!r} of "
                f"{getattr(fn, '__name__', type(fn).__name__)}() for the policy: "
                "use normal or keyword parameters"
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
        name = tool or getattr(fn, "__name__", None)
        if name is None:
            raise TypeError("@guard needs a tool name for this callable: guard('name')")
        if not re.fullmatch(TOOL_NAME_PATTERN, name):
            raise ValueError(f"tool name {name!r} isn't valid for Warden ({TOOL_NAME_PATTERN})")
        signature = _check_signature(fn)
        options: dict[str, Any] = {
            "client": client,
            "wait_for_approval": wait_for_approval,
            "poll_seconds": poll_seconds,
        }

        if _is_async(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                named = _named_arguments(signature, args, kwargs)
                return await run_guarded_async(
                    name, named, cast(Callable[..., Awaitable[Any]], fn), **options
                )

            return cast(Callable[P, R], async_wrapper)

        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            named = _named_arguments(signature, args, kwargs)
            return run_guarded(name, named, fn, **options)

        return wrapper

    return decorate
