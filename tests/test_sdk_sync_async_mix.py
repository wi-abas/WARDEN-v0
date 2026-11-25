"""run_guarded takes plain functions, run_guarded_async takes async ones. A mix is refused
before Warden is asked and before the tool runs, however the function is wrapped."""

import asyncio
import functools
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from pydantic import JsonValue

from warden.client import Answer
from warden.models import Decision
from warden.sdk import WardenClient, guard, run_guarded, run_guarded_async


class AllowAll(WardenClient):
    def __init__(self) -> None:
        super().__init__()
        self.asked = 0

    def evaluate(
        self, tool: str, arguments: dict[str, JsonValue], approval_id: str | None = None
    ) -> Answer:
        self.asked += 1
        return Answer(Decision.ALLOW, "ok")


ran: list[int] = []


@pytest.fixture(autouse=True)
def nothing_ran() -> None:
    ran.clear()


def sync_tool(x: int) -> int:
    ran.append(x)
    return x


async def async_tool(x: int) -> int:
    ran.append(x)
    return x


async def async_generator(x: int) -> Any:
    ran.append(x)
    yield x


class Tools:
    def __call__(self, x: int) -> int:
        return sync_tool(x)

    def method(self, x: int) -> int:
        return sync_tool(x)

    @staticmethod
    def static(x: int) -> int:
        return sync_tool(x)


class AsyncTools:
    async def __call__(self, x: int) -> int:
        return await async_tool(x)

    async def method(self, x: int) -> int:
        return await async_tool(x)


SYNC: list[Callable[..., Any]] = [
    sync_tool,
    lambda x: sync_tool(x),
    functools.partial(sync_tool),
    functools.partial(Tools()),
    Tools(),
    Tools().method,
    Tools.static,
    staticmethod(sync_tool),
]
ASYNC: list[Callable[..., Any]] = [
    async_tool,
    functools.partial(async_tool),
    functools.partial(functools.partial(async_tool)),
    functools.partial(AsyncTools()),
    AsyncTools(),
    AsyncTools().method,
    staticmethod(async_tool),
]


@pytest.mark.parametrize("fn", ASYNC)
def test_run_guarded_refuses_async(fn: Callable[..., Any]) -> None:
    client = AllowAll()
    with pytest.raises(TypeError, match="run_guarded_async"):
        run_guarded("t", {"x": 1}, fn, client=client)
    assert (client.asked, ran) == (0, [])


@pytest.mark.parametrize("fn", [*SYNC, async_generator])
def test_run_guarded_async_refuses_sync(fn: Callable[..., Any]) -> None:
    client = AllowAll()
    with pytest.raises(TypeError, match="async def"):
        asyncio.run(run_guarded_async("t", {"x": 1}, fn, client=client))
    assert (client.asked, ran) == (0, [])


@pytest.mark.parametrize("fn", SYNC)
def test_run_guarded_still_takes_sync(fn: Callable[..., Any]) -> None:
    assert run_guarded("t", {"x": 1}, fn, client=AllowAll()) == 1
    assert ran == [1]


@pytest.mark.parametrize("fn", ASYNC)
def test_run_guarded_async_still_takes_async(fn: Callable[..., Awaitable[int]]) -> None:
    assert asyncio.run(run_guarded_async("t", {"x": 1}, fn, client=AllowAll())) == 1
    assert ran == [1]


@pytest.mark.parametrize("fn", SYNC)
def test_guard_on_sync_callables(fn: Callable[..., Any]) -> None:
    assert guard("t", client=AllowAll())(fn)(x=1) == 1
    assert ran == [1]


@pytest.mark.parametrize("fn", ASYNC)
def test_guard_on_async_callables(fn: Callable[..., Any]) -> None:
    assert asyncio.run(guard("t", client=AllowAll())(fn)(x=1)) == 1
    assert ran == [1]


def test_guard_without_a_name_needs_one_for_nameless_callables() -> None:
    with pytest.raises(TypeError, match="tool name"):
        guard(client=AllowAll())(functools.partial(sync_tool))


def test_guard_names_the_bad_parameter_of_a_nameless_callable() -> None:
    def positional(x: int, /) -> None: ...

    with pytest.raises(TypeError, match="can't name parameter 'x'"):
        guard("t")(functools.partial(positional))
