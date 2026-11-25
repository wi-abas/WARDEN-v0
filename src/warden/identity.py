"""How Warden proves that it is Warden: the keys and the MACs, for both sides.

Without this, a client trusts whatever listens on Warden's port. With an agent token (or
the admin key), the client first sends a fresh random nonce to POST /v1/hello and checks
the MAC in the answer. Only then does it send the secret and the arguments, on the same
connection, and the answer to that carries a MAC too.

Only pure functions: the server (api.py) and the client (client.py) both use them, so
they can't drift apart. The exact bytes are pinned by tests/test_identity.py.
See docs/design/server-identity.md.
"""

import hashlib
import hmac
import re
import secrets
from typing import Any

HELLO_PATH = "/v1/hello"
NONCE_HEADER = "Warden-Nonce"
MAC_HEADER = "Warden-Mac"
NONCE_PATTERN = r"^[0-9a-f]{64}$"
KEY_ID_PATTERN = r"^[0-9a-f]{32}$"
_HEX_256 = re.compile(r"[0-9a-f]{64}")


def proof_key(secret: str) -> bytes:
    """The key K that proves Warden to whoever holds `secret` (token or admin key).
    Can't be turned back into the secret."""
    # surrogatepass: an odd secret must fail as a wrong one, not raise an error quoting it.
    raw = secret.encode("utf-8", "surrogatepass")
    return hmac.digest(raw, b"warden-server-identity-v1", "sha256")


def key_id(key: bytes) -> str:
    """Says which key is meant; reveals nothing about it."""
    return hashlib.sha256(b"warden-key-id-v1\n" + key).hexdigest()[:32]


def new_nonce() -> str:
    return secrets.token_hex(32)


def is_nonce(text: str) -> bool:
    return _HEX_256.fullmatch(text) is not None


def address(sockaddr: Any) -> str:
    """("127.0.0.1", 8000) -> "127.0.0.1:8000", ("::1", 8000, 0, 0) -> "[::1]:8000".
    ValueError for anything but a numeric host and a real port."""
    if not isinstance(sockaddr, tuple | list) or len(sockaddr) < 2:
        raise ValueError("not a TCP address")
    host, port = sockaddr[0], sockaddr[1]
    if not isinstance(host, str) or not re.fullmatch(r"[0-9A-Fa-f.:]{1,64}", host):
        raise ValueError("not a numeric host")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("not a TCP port")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def hello_mac(key: bytes, nonce: str, server: str, client: str) -> str:
    """Warden's answer to a hello. `server` and `client` are the two ends of this very
    connection: an impostor that passes the hello on to the real Warden has a connection
    of its own, with another client address (or another server port)."""
    return _mac(key, ["warden-hello-v1", nonce, server, client])


def answer_mac(
    key: bytes,
    *,
    nonce: str,
    server: str,
    client: str,
    method: str,
    target: bytes,
    request_sha256: str,
    status: int,
    retry_after: bytes,
    body: bytes,
) -> str:
    """Covers the question and the whole answer. `target` is the path with the query,
    exactly as sent; `retry_after` is the header's value (empty if there is none)."""
    return _mac(
        key,
        [
            "warden-answer-v1",
            nonce,
            server,
            client,
            method,
            target.hex(),  # hex: no byte in it can pass for a line break
            request_sha256,
            str(status),
            retry_after.hex(),
            hashlib.sha256(body).hexdigest(),
        ],
    )


def _mac(key: bytes, lines: list[str]) -> str:
    return hmac.digest(key, "\n".join(lines).encode("ascii"), "sha256").hex()


def same_mac(expected: str, received: object) -> bool:
    """True if `received` is exactly `expected` (64 lowercase hex digits). Constant time."""
    return (
        isinstance(received, str)
        and _HEX_256.fullmatch(received) is not None
        and hmac.compare_digest(expected, received)
    )
