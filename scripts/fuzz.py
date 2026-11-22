"""Coverage-guided fuzzing of Warden with Atheris (libFuzzer for Python). Linux only.

    uv sync --group fuzz
    uv run python scripts/fuzz.py TARGET [libFuzzer options]
    uv run python scripts/fuzz.py bypass -max_total_time=300

Targets live in tests/fuzz_targets.py (policy, evaluate, bypass, proxy, http); each
raises only on a real bug, with an independent oracle. The same targets also run
through Hypothesis in the normal test suite (tests/test_fuzz_targets.py).

On a failure libFuzzer prints the input (and saves it as crash-*): add it as a
regression test, then fix. Atheris doesn't build on macOS (it needs a libFuzzer
clang); CI runs it weekly on Linux (.github/workflows/fuzz.yml).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

import atheris  # type: ignore[import-untyped]  # noqa: E402 (path set up first)

with atheris.instrument_imports():
    from fuzz_targets import TARGETS  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        sys.exit(f"usage: fuzz.py {{{','.join(sorted(TARGETS))}}} [libFuzzer options]")
    target = TARGETS[sys.argv[1]]
    atheris.Setup([sys.argv[0], *sys.argv[2:]], target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
