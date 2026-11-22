"""The shipped default policy (also what `warden init` writes) behaves as documented."""

import pytest

from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import DEFAULT_POLICY_PATH, load_policy


@pytest.mark.parametrize(
    ("tool", "arguments", "expected"),
    [
        ("read_file", {"path": "/workspace/notes.md"}, Decision.ALLOW),
        ("read_file", {"path": "/etc/passwd"}, Decision.DENY),
        ("read_file", {"path": "/workspace/../etc/passwd"}, Decision.DENY),
        ("write_file", {"path": "/workspace/a.txt", "content": "x"}, Decision.REQUIRE_APPROVAL),
        ("write_file", {"path": "/home/a.txt", "content": "x"}, Decision.DENY),
        ("delete_file", {"path": "/workspace/a.txt"}, Decision.DENY),
        ("send_email", {"to": "bob@example.com"}, Decision.ALLOW),
        ("send_email", {"to": "Bob@EXAMPLE.com"}, Decision.ALLOW),
        ("send_email", {"to": "bob@gmail.com"}, Decision.DENY),
        ("send_email", {"to": "bob@example.com", "bcc": "x@evil.com"}, Decision.DENY),
        ("run_shell", {"cmd": "ls"}, Decision.DENY),
    ],
)
def test_default_policy(tool: str, arguments: dict, expected: Decision) -> None:
    policy = load_policy(DEFAULT_POLICY_PATH)
    request = ActionRequest.model_validate({"agent_id": "a", "tool": tool, "arguments": arguments})
    assert evaluate(request, policy.rules, policy.tools).decision == expected
