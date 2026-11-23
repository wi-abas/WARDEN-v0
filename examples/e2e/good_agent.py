"""A well-behaved agent: WardenClient and @guard doing normal work.

Phase "first": allowed calls run, denied ones don't, approvals are queued, failures to
reach Warden fail closed. Phase "retry" (after run_all.sh approved the delete and rejected
the email): the approved call runs once; a replay, a changed call, or a rejected one is
queued again instead of running.
"""

import os
import sys
from collections.abc import Callable

from e2e_common import URL, check, token

from warden.client import ClientConfigError, WardenClient
from warden.sdk import ApprovalPending, NotAllowed, guard, run_guarded

client = WardenClient(URL, "good-agent", token=token("good-agent"))
RAN: list[tuple[str, str]] = []


@guard(client=client)
def read_file(path: str) -> str:
    RAN.append(("read_file", path))
    return f"contents of {path}"


@guard(client=client)
def write_file(path: str, content: str) -> str:
    RAN.append(("write_file", path))
    return "ok"


@guard(client=client)
def send_email(to: str, subject: str = "", body: str = "") -> str:
    RAN.append(("send_email", to))
    return "sent"


@guard(client=client)
def shell(command: str) -> str:
    RAN.append(("shell", command))
    return "ran"


@guard(client=client)
def delete_file(path: str) -> str:
    RAN.append(("delete_file", path))
    return "deleted"


def outcome(fn: Callable[[], str]) -> str:
    """'ran', 'pending' or 'blocked: <reason>'."""
    try:
        fn()
    except ApprovalPending:
        return "pending"
    except NotAllowed as error:
        return f"blocked: {error.answer.reason}"
    return "ran"


def first() -> None:
    answer = client.evaluate("read_file", {"path": "/workspace/notes.txt"})
    check("client: read in /workspace allowed", answer.decision.value == "allow", answer.reason)
    check("guard: read /workspace ran", outcome(lambda: read_file("/workspace/notes.txt")) == "ran")
    got = outcome(lambda: read_file("/etc/passwd"))
    check("guard: read /etc/passwd blocked", got == "blocked: no matching rule", got)
    got = outcome(lambda: write_file("/workspace/out.txt", "GOODSECRET-content-123"))
    check("guard: write /workspace ran", got == "ran", got)
    got = outcome(lambda: send_email("bob@example.com", "hi", "GOODSECRET-body-456"))
    check("guard: email to colleague ran", got == "ran", got)
    got = outcome(lambda: send_email("ann@partner.org", "q", "GOODSECRET-partner-789"))
    check("guard: email to partner needs approval", got == "pending", got)
    got = outcome(lambda: shell("rm -rf /"))
    check("guard: shell blocked", got == "blocked: No shell for agents", got)
    got = outcome(lambda: delete_file("/workspace/old.txt"))
    check("guard: delete needs approval", got == "pending", got)
    result = run_guarded(
        "read_file", {"path": "/workspace/x.txt"}, lambda path: f"r:{path}", client=client
    )
    check("run_guarded: allowed call ran", result == "r:/workspace/x.txt", result)

    unreachable = WardenClient(f"http://127.0.0.1:{os.environ['E2E_DEAD_PORT']}", "good-agent")
    answer = unreachable.evaluate("read_file", {"path": "/workspace/a"})
    check("client: unreachable Warden fails closed", answer.decision.value == "deny", answer)
    try:
        WardenClient("http://evil.example.com:8787")
        refused = False
    except ClientConfigError:
        refused = True
    check("client: remote Warden URL refused", refused)
    expected = [
        ("read_file", "/workspace/notes.txt"),
        ("write_file", "/workspace/out.txt"),
        ("send_email", "bob@example.com"),
    ]
    check("guard: only allowed calls ran", RAN == expected, RAN)


def retry() -> None:
    got = outcome(lambda: delete_file("/workspace/old.txt"))
    check("approved delete runs", got == "ran", got)
    got = outcome(lambda: delete_file("/workspace/old.txt"))
    check("approved delete runs only once (replay re-queued)", got == "pending", got)
    got = outcome(lambda: delete_file("/workspace/other.txt"))
    check("changed delete is not approved", got == "pending", got)
    got = outcome(lambda: send_email("ann@partner.org", "q", "GOODSECRET-partner-789"))
    check("rejected email does not run (re-queued)", got == "pending", got)
    check("retry: only the approved delete ran", RAN == [("delete_file", "/workspace/old.txt")])


if __name__ == "__main__":
    {"first": first, "retry": retry}[sys.argv[1]]()
