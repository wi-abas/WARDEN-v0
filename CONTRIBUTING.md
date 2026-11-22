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

`tests/test_properties.py` uses [Hypothesis](https://hypothesis.readthedocs.io/) to try
hundreds of generated inputs per rule (engine, fingerprints, approvals, bypass attempts).
Before a security-relevant change, run it much harder:

```sh
HYPOTHESIS_PROFILE=deep uv run pytest tests/test_properties.py   # 5,000 inputs per rule
```

## Rules

- **Decisions stay deterministic.** No network, no randomness, no LLMs in the policy engine.
- **Fail closed.** Anything unexpected must end in `deny`, never `allow`.
- **Never log or store tool arguments.** They may contain secrets.
- **Every security-relevant change needs tests**, including the attack it prevents.
- **Small pull requests.** One change, explained in plain language.
- **New dependencies need a reason** in the pull request description.

Found a vulnerability? Don't open an issue, see [SECURITY.md](SECURITY.md).
