"""The sample policy and tests under "Common patterns" in docs/policies.md really work."""

import json
import re
from pathlib import Path

import pytest

from warden.cli import main
from warden.engine import evaluate
from warden.models import ActionRequest, Decision
from warden.policy import parse_policy

DOC = Path(__file__).parent.parent / "docs" / "policies.md"


def sample(tmp_path: Path) -> tuple[Path, Path]:
    """The section's two JSON blocks, saved under the names the docs use."""
    section = DOC.read_text(encoding="utf-8").split("\n## Common patterns\n")[1].split("\n## ")[0]
    policy_text, tests_text = re.findall(r"```json\n(.*?)```", section, flags=re.DOTALL)
    policy, tests = tmp_path / "policy.json", tmp_path / "policy-tests.json"
    policy.write_text(policy_text, encoding="utf-8")
    tests.write_text(tests_text, encoding="utf-8")
    policy.chmod(0o644)
    return policy, tests


def test_sample_policy_passes_the_strict_check(tmp_path: Path) -> None:
    policy, _ = sample(tmp_path)
    assert main(["check", str(policy), "--strict"]) == 0


def test_sample_tests_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, tests = sample(tmp_path)
    assert main(["test", str(tests)]) == 0, capsys.readouterr().out


@pytest.mark.parametrize(
    ("arguments", "required", "expected"),
    [
        ({"to": "Ann@MyCompany.com"}, True, Decision.ALLOW),
        ({"to": "bob@gmail.com"}, True, Decision.REQUIRE_APPROVAL),
        ({"to": "ann@mycompany.com", "bcc": "x@evil.net"}, True, Decision.DENY),
        ({"subject": "hi"}, True, Decision.DENY),
        ({"subject": "hi"}, False, Decision.REQUIRE_APPROVAL),
    ],
)
def test_what_the_text_says_about_email(
    tmp_path: Path, arguments: dict[str, str], required: bool, expected: Decision
) -> None:
    data = json.loads(sample(tmp_path)[0].read_text(encoding="utf-8"))
    if not required:
        del data["tools"]["send_email"]["required"]
    policy = parse_policy(json.dumps(data))
    request = ActionRequest(agent_id="a", tool="send_email", arguments={**arguments})
    assert evaluate(request, policy.rules, policy.tools).decision is expected
