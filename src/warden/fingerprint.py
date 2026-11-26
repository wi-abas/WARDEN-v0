"""Action fingerprints: a SHA-256 hash that identifies one exact action.

Later, an approval will be tied to this hash. If anything about the action
changes (a different amount, recipient, tool or agent), the hash changes too,
so the old approval no longer matches.

How it works:
1. Take agent_id, tool and arguments.
2. Write them as "canonical" JSON: keys sorted, no extra spaces. That way the
   same action always produces the same text, whatever order the keys came in.
3. Hash that text with SHA-256, prefixed with a version label so the format
   can change in the future without old and new hashes being confused.

The server passes a secret key (hash_key.py), which makes it an HMAC: without the key,
nobody holding a copy of the database can guess arguments by hashing likely values
(docs/design/keyed-action-hash.md). Without a key it is a plain SHA-256, for places
where nothing is stored (`warden test`, library use of engine.evaluate).
"""

import hashlib
import hmac
import json

from warden.models import ActionRequest

FINGERPRINT_VERSION = "warden-action-v1"


def canonical_json(request: ActionRequest) -> str:
    data = {"agent_id": request.agent_id, "tool": request.tool, "arguments": request.arguments}
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,  # mutation-ok: models.py already refuses NaN and infinity
    )


def fingerprint(request: ActionRequest, key: bytes | None = None) -> str:
    """Return a 64-character hex hash identifying this exact action: HMAC-SHA256 with
    `key` if given, else plain SHA-256."""
    text = f"{FINGERPRINT_VERSION}\n{canonical_json(request)}".encode()
    if key is not None:
        return hmac.new(key, text, hashlib.sha256).hexdigest()
    return hashlib.sha256(text).hexdigest()
