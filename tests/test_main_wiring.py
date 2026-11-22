"""api.main() wires settings into the real server; engine safety nets fail closed."""

from pathlib import Path
from typing import Any

import pytest
import uvicorn
from helpers import BASIC_POLICY

import warden.api
from warden.engine import evaluate
from warden.models import ActionRequest, Condition, Decision, Op, Rule
from warden.settings import Settings


def test_main_starts_uvicorn_with_the_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append({"app": app, **kw}))
    settings = Settings(
        policy=BASIC_POLICY,
        port=9123,
        audit_db=tmp_path / "audit.db",
        retention_days=7,
        admin_key="k" * 32,
    )
    warden.api.main(settings)
    [call] = calls
    assert (call["host"], call["port"]) == ("127.0.0.1", 9123)
    assert "warden" in call["log_config"]["loggers"]
    assert (tmp_path / "audit.db").exists()
    err = capsys.readouterr().err
    assert "using WARDEN_ADMIN_KEY" in err and "k" * 32 not in err


@pytest.mark.parametrize(
    ("op", "bad_value"), [(Op.GT, "not a number"), (Op.STARTSWITH, 5), (Op.ENDSWITH, None)]
)
def test_policy_values_that_skipped_validation_still_fail_closed(op: Op, bad_value: Any) -> None:
    # model_construct skips validation, simulating a bug that let a bad value through.
    condition = Condition.model_construct(arg="x", op=op, value=bad_value, ignore_case=False)
    rule = Rule.model_construct(
        id="r", tool="t", effect=Decision.ALLOW, when=(condition,), message=None
    )
    request = ActionRequest.model_validate(
        {"agent_id": "a", "tool": "t", "arguments": {"x": "a" if op is not Op.GT else 1}}
    )
    result = evaluate(request, [rule])
    assert (result.decision, result.reason) == (Decision.DENY, "evaluation error")
