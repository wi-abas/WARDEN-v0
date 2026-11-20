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
"""

import hashlib
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
        allow_nan=False,
    )


def fingerprint(request: ActionRequest) -> str:
    """Return a 64-character hex SHA-256 hash identifying this exact action."""
    text = f"{FINGERPRINT_VERSION}\n{canonical_json(request)}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
