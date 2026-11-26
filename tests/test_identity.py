"""The MACs that prove Warden to its clients: the exact bytes, and what they cover."""

import hashlib
import hmac
from typing import Any

import pytest

from warden import identity
from warden.identity import (
    address,
    answer_mac,
    client_hello_mac,
    hello_mac,
    is_nonce,
    key_id,
    new_nonce,
    same_mac,
)

TOKEN = "wdn_" + "A" * 43
NONCE = "0123456789abcdef" * 4
SERVER, CLIENT = "127.0.0.1:8000", "127.0.0.1:54321"
KEY = identity.proof_key(TOKEN)
ANSWER: dict[str, Any] = {
    "nonce": NONCE,
    "server": SERVER,
    "client": CLIENT,
    "method": "POST",
    "target": b"/v1/evaluate",
    "request_sha256": hashlib.sha256(b'{"tool": "t", "arguments": {}}').hexdigest(),
    "status": 429,
    "retry_after": b"7",
    "body": b'{"decision": "deny"}',
}

# Fixed values (the key also checked with openssl): neither side may change alone.
VECTOR_KEY = "4d0306e0db89012f03fd119092430ef4afc2e99812ccb9b35ada12e17982d08c"
VECTOR_KEY_ID = "d2da178a17bf89b30d2fe1bc5a60cdc0"
VECTOR_HELLO = "e74c5129313ddb55a7d909aa76c2e190779699c10cf52e50ab4bf732bd2ba18d"
VECTOR_ANSWER = "7b015374a6d3a1f280a6432bb0743b0663d756ae3c13cc5cb9bbd00b6fa0e001"


def test_fixed_vectors() -> None:
    assert KEY.hex() == VECTOR_KEY
    assert key_id(KEY) == VECTOR_KEY_ID
    assert hello_mac(KEY, NONCE, SERVER, CLIENT) == VECTOR_HELLO
    assert answer_mac(KEY, **ANSWER) == VECTOR_ANSWER


def test_the_construction_written_out() -> None:
    """The same values from the text of docs/design/server-identity.md, by hand."""

    def mac(key: bytes, message: str) -> str:
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    key = bytes.fromhex(mac(TOKEN.encode(), "warden-server-identity-v1"))
    assert key == KEY
    assert key_id(key) == hashlib.sha256(b"warden-key-id-v1\n" + key).hexdigest()[:32]
    hello = f"warden-hello-v1\n{NONCE}\n{SERVER}\n{CLIENT}"
    assert hello_mac(KEY, NONCE, SERVER, CLIENT) == mac(key, hello)
    answer = (
        f"warden-answer-v1\n{NONCE}\n{SERVER}\n{CLIENT}\nPOST\n{b'/v1/evaluate'.hex()}\n"
        f"{ANSWER['request_sha256']}\n429\n{b'7'.hex()}\n"
        f"{hashlib.sha256(ANSWER['body']).hexdigest()}"
    )
    assert answer_mac(KEY, **ANSWER) == mac(key, answer)


@pytest.mark.parametrize(
    ("field", "other"),
    [
        ("nonce", "f" * 64),
        ("server", "127.0.0.1:8001"),
        ("client", "127.0.0.1:54322"),
        ("method", "GET"),
        ("target", b"/v1/evaluate?x=1"),
        ("request_sha256", "0" * 64),
        ("status", 200),
        ("retry_after", b""),
        ("body", b'{"decision": "allow"}'),
    ],
)
def test_every_field_counts(field: str, other: object) -> None:
    assert answer_mac(KEY, **{**ANSWER, field: other}) != answer_mac(KEY, **ANSWER)


def test_hello_covers_nonce_both_addresses_and_key() -> None:
    macs = {
        hello_mac(KEY, NONCE, SERVER, CLIENT),
        hello_mac(KEY, "f" * 64, SERVER, CLIENT),
        hello_mac(KEY, NONCE, "[::1]:8000", CLIENT),
        hello_mac(KEY, NONCE, SERVER, "127.0.0.1:1"),
        hello_mac(KEY, NONCE, CLIENT, SERVER),
        hello_mac(identity.proof_key(TOKEN + "B"), NONCE, SERVER, CLIENT),
        answer_mac(KEY, **ANSWER),
    }
    assert len(macs) == 7


@pytest.mark.parametrize(
    "received",
    [
        None,
        "",
        b"a" * 64,
        VECTOR_HELLO.upper(),
        VECTOR_HELLO[:-1],
        VECTOR_HELLO + "0",
        VECTOR_HELLO + "\n",
        " " + VECTOR_HELLO,
        "٣" * 64,
        ["a"],
    ],
)
def test_only_exactly_the_mac_is_accepted(received: object) -> None:
    assert same_mac(VECTOR_HELLO, VECTOR_HELLO)
    assert not same_mac(VECTOR_HELLO, received)


def test_one_changed_digit_is_refused() -> None:
    for i, digit in enumerate(VECTOR_HELLO):
        changed = VECTOR_HELLO[:i] + ("0" if digit != "0" else "1") + VECTOR_HELLO[i + 1 :]
        assert not same_mac(VECTOR_HELLO, changed)


def test_macs_are_compared_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    compared: list[tuple[str, str]] = []

    def record(a: str, b: str) -> bool:
        compared.append((a, b))
        return True

    monkeypatch.setattr("warden.identity.hmac.compare_digest", record)
    assert same_mac("a" * 64, "b" * 64)  # its answer is the one that counts
    assert compared == [("a" * 64, "b" * 64)]


def test_nonces() -> None:
    first, second = new_nonce(), new_nonce()
    assert first != second and is_nonce(first)
    for bad in ("", "A" * 64, first[1:], first + "0", first + "\n", first[:-1] + "g"):
        assert not is_nonce(bad)


def test_addresses() -> None:
    assert address(("127.0.0.1", 8000)) == "127.0.0.1:8000"
    assert address(["127.0.0.1", 1]) == "127.0.0.1:1"
    assert address(("::1", 65535, 0, 0)) == "[::1]:65535"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "/run/warden.sock",
        ("127.0.0.1",),
        ("127.0.0.1", None),
        ("127.0.0.1", 0),
        ("127.0.0.1", 65536),
        ("localhost", 8000),
        ("", 8000),
        ("127.0.0.1\n", 8000),
        (None, 8000),
    ],
)
def test_odd_addresses_are_refused(bad: object) -> None:
    with pytest.raises(ValueError):
        address(bad)


def test_odd_secrets_dont_raise() -> None:
    """An error here would quote the secret."""
    assert identity.proof_key("wdn_\udcff") != identity.proof_key("wdn_")


VECTOR_CLIENT_HELLO = "aca286eb25cdd10901557b2be1e3788346b63ca6e59b98bdeb828de1c0ab8000"


def test_client_hello_vector_and_construction() -> None:
    assert client_hello_mac(KEY, NONCE, SERVER, CLIENT) == VECTOR_CLIENT_HELLO
    message = f"warden-client-hello-v1\n{NONCE}\n{SERVER}\n{CLIENT}".encode()
    assert VECTOR_CLIENT_HELLO == hmac.new(KEY, message, hashlib.sha256).hexdigest()
    # Never the same as Warden's own hello MAC: one can't stand in for the other.
    assert VECTOR_CLIENT_HELLO != hello_mac(KEY, NONCE, SERVER, CLIENT)
    assert client_hello_mac(KEY, NONCE, SERVER, "127.0.0.1:1") != VECTOR_CLIENT_HELLO
