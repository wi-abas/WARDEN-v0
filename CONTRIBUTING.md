# Contributing

Thanks for helping. Warden is a security tool, so changes are kept small and tested.

## Setup

```sh
uv sync
uv run pytest
```

## Before opening a pull request

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest --cov
```

All four must pass (CI runs the same).

The end-to-end scenario (real server, fake agents, MCP proxy; part of `pytest`) also runs on its own: `bash examples/e2e/run_all.sh` (see `examples/e2e/README.md`).

`tests/test_properties.py` uses [Hypothesis](https://hypothesis.readthedocs.io/) to try
hundreds of generated inputs per rule (engine, fingerprints, approvals, bypass attempts).
Before a security-relevant change, run it much harder:

```sh
HYPOTHESIS_PROFILE=deep uv run pytest tests/test_properties.py   # 5,000 inputs per rule
```

### Fuzzing

`tests/fuzz_targets.py` holds five fuzz targets (policy parsing, evaluation, path / URL /
email bypasses, the MCP proxy, the HTTP API). Each fails only on a real bug, checked
against an independent oracle. They run in the normal test suite through Hypothesis:

```sh
HYPOTHESIS_PROFILE=deep uv run pytest tests/test_fuzz_targets.py   # 5,000 inputs each
```

CI also runs them weekly with coverage guidance through
[Atheris](https://github.com/google/atheris) (`.github/workflows/fuzz.yml`). On Linux:

```sh
uv sync --group fuzz
uv run python scripts/fuzz.py bypass -max_total_time=300
```

Atheris doesn't build on macOS. When a target fails, add the input as a regression test
first, then fix.

## Rules

- **Decisions stay deterministic.** No network, no randomness, no LLMs in the policy engine.
- **Fail closed.** Anything unexpected must end in `deny`, never `allow`.
- **Never log or store tool arguments.** They may contain secrets.
- **Every security-relevant change needs tests**, including the attack it prevents.
- **Small pull requests.** One change, explained in plain language.
- **New dependencies need a reason** in the pull request description.

Found a vulnerability? Don't open an issue, see [SECURITY.md](SECURITY.md).
