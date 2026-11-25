"""What the SDK says when it can't check an argument, and dict keys that aren't text."""

import asyncio
from typing import Any

import pytest
from test_sdk import FakeClient

from warden.sdk import NotAllowed, freeze, guard, run_guarded, run_guarded_async


class Mailer:
    sent: list[str]

    def __init__(self, client: FakeClient) -> None:
        self.sent = []
        self.send = guard("send_email", client=client)(self._send)

    def _send(self, to: str) -> None:
        self.sent.append(to)


def test_guarding_a_method_says_what_to_do_instead() -> None:
    client = FakeClient()

    class Wrong:
        @guard(client=client)
        def send(self, to: str) -> None:
            raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match=r"argument 'self' .*guard\('tool_name'\)\(obj.method"):
        Wrong().send("a@x.com")
    assert client.asked == []


def test_a_guarded_bound_method_works() -> None:
    client = FakeClient()
    mailer = Mailer(client)
    mailer.send("a@x.com")
    assert mailer.sent == ["a@x.com"] and client.asked[0][1] == {"to": "a@x.com"}


def test_the_refusal_names_the_argument_not_its_value() -> None:
    with pytest.raises(NotAllowed) as caught:
        run_guarded("t", {"ok": 1, "bad": b"s3cret"}, print, client=FakeClient())
    assert "'bad'" in caught.value.answer.reason and "s3cret" not in caught.value.answer.reason
    assert "method" not in caught.value.answer.reason

    async def tool(**kwargs: Any) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="'bad'"):
        asyncio.run(run_guarded_async("t", {"bad": {1}}, tool, client=FakeClient()))


def test_odd_argument_names_are_shown_safely() -> None:
    def tool(**kwargs: Any) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed) as caught:
        run_guarded("t", {"\n\u202e" + "x" * 500: object()}, tool, client=FakeClient())
    reason = caught.value.answer.reason
    assert reason.isascii() and reason.isprintable() and len(reason) < 200
    with pytest.raises(NotAllowed, match="arguments are not plain JSON"):
        run_guarded("t", {"\ud800": 1}, tool, client=FakeClient())


class Same(str):
    """Equal only to itself, but JSON writes it as ordinary text."""

    __hash__ = str.__hash__

    def __eq__(self, other: object) -> bool:
        return self is other


@pytest.mark.parametrize(
    "value",
    [
        {1: "a", "1": "b"},
        {1: "a"},
        {True: "a", "true": "b"},
        {None: "a"},
        {1.5: "a"},
        [{"deep": ({2: "x"},)}],
        {"k": 1, Same("k"): 2},
    ],
)
def test_dict_keys_json_would_change_are_refused(value: Any) -> None:
    client = FakeClient()

    @guard(client=client)
    def tool(x: Any) -> None:
        raise AssertionError("must not run")

    with pytest.raises(NotAllowed, match="argument 'x'"):
        tool(value)
    assert client.asked == []


def test_top_level_names_must_be_text() -> None:
    arguments: dict[Any, Any] = {1: "a"}
    assert freeze(arguments) is None
    with pytest.raises(NotAllowed, match="plain JSON"):
        run_guarded("t", arguments, print, client=FakeClient())
