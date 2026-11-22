"""Shared test helpers."""

from pathlib import Path

# A small, fixed policy for tests (allow read_file, approve send_email, deny delete_file).
# Tests use this instead of policies/default.json, so the default can evolve freely.
BASIC_POLICY = Path(__file__).parent / "fixtures" / "basic-policy.json"
