"""flood-bot (policy limits: 20 requests/minute, 3 pending approvals) floods Warden.

Its pending approvals are capped, its requests get 429 with Retry-After, and other
agents are not affected.
"""

import collections

from e2e_common import check, evaluate, token

FLOOD = token("flood-bot")

if __name__ == "__main__":
    print("--- pending approvals quota (max 3)")
    got = []
    for i in range(5):
        body = evaluate("delete_file", {"path": f"/workspace/flood-{i}.txt"}, FLOOD)[1]
        got.append(body.get("decision"))
    want = ["require_approval"] * 3 + ["deny"] * 2
    check("4th and 5th pending approvals refused", got == want, got)
    body = evaluate("delete_file", {"path": "/workspace/flood-0.txt"}, FLOOD)[1]
    check(
        "asking again for a pending action is not a new one",
        body.get("decision") == "require_approval",
    )

    print("--- request flood")
    counts: collections.Counter[tuple[int, str]] = collections.Counter()
    retry_after = set()
    for _ in range(60):
        status, body, headers = evaluate("read_file", {"path": "/workspace/a"}, FLOOD)
        counts[(status, body.get("decision"))] += 1
        if status == 429:
            retry_after.add(headers.get("retry-after"))
    check("flood gets 429 deny", counts[(429, "deny")] > 0, dict(counts))
    check("flood never gets more than its limit", counts[(200, "allow")] <= 20, dict(counts))
    check("429 carries Retry-After", bool(retry_after) and None not in retry_after, retry_after)
    status, body, _headers = evaluate("read_file", {"path": "/workspace/a"}, token("good-agent"))
    check("another agent is unaffected by the flood", body.get("decision") == "allow", status)
    response = evaluate(
        "read_file", {"path": "/workspace/a"}, None, extra={"agent_id": "flood-bot"}
    )
    check("no token, claiming to be flood-bot -> 401", response[0] == 401)
