"""A minimal agent loop guarded by Warden, using only Python's standard library.

Copy `ask_warden` and `guarded` into your own agent: call `guarded(...)` instead of
calling a tool directly.

Run it (two terminals):
    1)  WARDEN_ADMIN_KEY=$(openssl rand -hex 32) \\
          uv run warden serve --policy examples/demo-policy.json
    2)  uv run python examples/agent.py
When the agent waits for approval, review and approve it from a third terminal (with
the same WARDEN_ADMIN_KEY set) with the command it prints.
"""

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

WARDEN_URL = os.environ.get("WARDEN_URL", "http://127.0.0.1:8000")


class NotAllowed(Exception):
    """Warden didn't say allow, so the tool did not run."""


def ask_warden(
    tool: str, arguments: dict[str, Any], approval_id: str | None = None, url: str = WARDEN_URL
) -> dict[str, Any]:
    body: dict[str, Any] = {"agent_id": "example-agent", "tool": tool, "arguments": arguments}
    if approval_id:
        body["approval_id"] = approval_id
    request = urllib.request.Request(  # noqa: S310 (URL is our own Warden server)
        f"{url}/v1/evaluate",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            answer: dict[str, Any] = json.load(response)
            return answer
    except urllib.error.HTTPError as error:  # Warden's error bodies also say "deny"
        return {"decision": "deny", "reason": f"Warden returned HTTP {error.code}"}
    except (OSError, ValueError):  # unreachable, timeout, garbage: fail closed
        return {"decision": "deny", "reason": "Warden unreachable"}


def guarded(
    tool: str,
    arguments: dict[str, Any],
    run: Callable[..., Any],
    *,
    url: str = WARDEN_URL,
    wait_seconds: float = 300,
    poll_every: float = 2.0,
) -> Any:
    """Run `run(**arguments)` only if Warden says allow. Waits for human approval.

    The tool runs with a frozen COPY of exactly what Warden checked: if the caller's
    dict (or a list inside it) changes after the check, the change is not used.
    """
    arguments = json.loads(json.dumps(arguments))  # snapshot: checked == executed
    answer = ask_warden(tool, arguments, url=url)
    if answer.get("decision") == "require_approval" and answer.get("approval_id"):
        approval_id = answer["approval_id"]
        # The human must see the action first: `warden approvals approve` lists it,
        # shows it and sends its action_hash (Warden refuses an approve without one).
        print(f"   ⏳ {answer.get('reason')}. Review and approve with:")
        print(f"      warden approvals approve {approval_id} --warden-url {url}")
        deadline = time.monotonic() + wait_seconds
        while answer.get("decision") == "require_approval":
            if time.monotonic() > deadline:
                raise NotAllowed("gave up waiting for approval")
            time.sleep(poll_every)
            answer = ask_warden(tool, arguments, approval_id, url=url)
    if answer.get("decision") != "allow":  # fail closed: anything but "allow" means no
        raise NotAllowed(answer.get("reason", "no answer"))
    return run(**arguments)


# --- Pretend tools and a pretend LLM plan ----------------------------------------------


def read_file(path: str) -> str:
    return f"(contents of {path})"


def delete_file(path: str) -> str:
    return f"deleted {path}"


def send_invoice(to: str, amount: int) -> str:
    return f"invoice of €{amount} sent to {to}"


TOOLS: dict[str, Callable[..., str]] = {
    "read_file": read_file,
    "delete_file": delete_file,
    "send_invoice": send_invoice,
}

PLAN: list[tuple[str, dict[str, Any]]] = [
    ("read_file", {"path": "/data/report.txt"}),
    ("delete_file", {"path": "/data/report.txt"}),
    ("send_invoice", {"to": "acme", "amount": 200}),
    ("send_invoice", {"to": "acme", "amount": 5000}),
]


def main(url: str = WARDEN_URL, poll_every: float = 2.0) -> list[str]:
    outcomes = []
    for tool, arguments in PLAN:
        print(f"Agent wants: {tool} {arguments}")
        try:
            result = guarded(tool, arguments, TOOLS[tool], url=url, poll_every=poll_every)
            print(f"   ✅ ran: {result}\n")
            outcomes.append(f"ran {tool}")
        except NotAllowed as reason:
            print(f"   ⛔ not run: {reason}\n")
            outcomes.append(f"blocked {tool}")
    return outcomes


if __name__ == "__main__":
    main()
