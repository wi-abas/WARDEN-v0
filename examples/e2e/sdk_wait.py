"""@guard(wait_for_approval=...): the call waits while a human decides.

Approved: the function runs. Rejected: it doesn't. Calling again after a rejection asks
for a new approval instead of running.
"""

import threading

from e2e_common import URL, check, decide, token, wait_for_pending

from warden.client import WardenClient
from warden.sdk import ApprovalPending, NotAllowed, guard

client = WardenClient(URL, "good-agent", token=token("good-agent"))
RAN: list[str] = []


@guard("delete_file", client=client, wait_for_approval=8, poll_seconds=0.2)
def delete_file(path: str) -> str:
    RAN.append(path)
    return "deleted"


def human(path: str, approve: bool) -> None:
    decide(wait_for_pending("good-agent", "delete_file", {"path": path}), approve)


def run(path: str, approve: bool) -> str:
    threading.Thread(target=human, args=(path, approve), daemon=True).start()
    try:
        return f"ran: {delete_file(path)}"
    except NotAllowed as error:
        return f"not run: {error.answer.reason}"


if __name__ == "__main__":
    got = run("/workspace/sdk-ok.txt", approve=True)
    check("sdk wait: approved call runs", got == "ran: deleted", got)
    got = run("/workspace/sdk-no.txt", approve=False)
    check("sdk wait: rejected call doesn't run", got == "not run: denied by a human", got)
    try:
        guard("delete_file", client=client)(lambda path: "x")("/workspace/sdk-no.txt")
        again = "ran"
    except ApprovalPending:
        again = "pending"
    except NotAllowed as error:
        again = f"blocked: {error.answer.reason}"
    check("sdk: retry after a rejection asks again (doesn't run)", again == "pending", again)
    check("sdk: only the approved call ran", RAN == ["/workspace/sdk-ok.txt"], RAN)
