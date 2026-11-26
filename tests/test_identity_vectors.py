"""docs/identity-test-vectors.json: the fixed values other-language clients check against.
They must always match src/warden/identity.py."""

import hashlib
import json
from pathlib import Path

from warden import identity

VECTORS = json.loads(
    (Path(__file__).parent.parent / "docs" / "identity-test-vectors.json").read_text()
)


def test_vectors_file_matches_the_python_implementation() -> None:
    v = VECTORS
    key = identity.proof_key(v["token"])
    assert key.hex() == v["proof_key_hex"]
    assert identity.key_id(key) == v["key_id"]
    assert identity.hello_mac(key, v["nonce"], v["server"], v["client"]) == v["hello_mac"]
    client_mac = identity.client_hello_mac(key, v["nonce"], v["server"], v["client"])
    assert client_mac == v["client_hello_mac"]
    a = v["answer"]
    assert a["mac"] == identity.answer_mac(
        key,
        nonce=v["nonce"],
        server=v["server"],
        client=v["client"],
        method=a["method"],
        target=a["target"].encode("ascii"),
        request_sha256=hashlib.sha256(a["request_body"].encode()).hexdigest(),
        status=a["status"],
        retry_after=a["retry_after"].encode("latin-1"),
        body=a["body"].encode(),
    )
