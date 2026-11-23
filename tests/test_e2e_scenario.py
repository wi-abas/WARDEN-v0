"""Runs the end-to-end scenario (examples/e2e/run_all.sh) against real processes.

A real `warden serve`, agents over HTTP, `warden proxy` with a fake MCP server, the
approvals CLI, a restart and audit checks. Takes about 10-15 seconds.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

RUN_ALL = Path(__file__).parent.parent / "examples" / "e2e" / "run_all.sh"


@pytest.mark.skipif(shutil.which("bash") is None or os.name != "posix", reason="needs bash")
def test_end_to_end_scenario_passes() -> None:
    env = {**os.environ, "E2E_PYTHON": sys.executable}
    env.pop("WARDEN_ADMIN_KEY", None)
    result = subprocess.run(  # noqa: S603 (our own script)
        ["bash", str(RUN_ALL)],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        check=False,
    )
    output = result.stdout + result.stderr
    failures = [line for line in output.splitlines() if line.startswith("FAIL")]
    assert result.returncode == 0, "\n".join(failures) or output[-3000:]
    assert ", 0 failed" in output
