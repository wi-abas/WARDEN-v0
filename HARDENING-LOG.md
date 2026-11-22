# Hardening log: batch 1

Branch `hardening/batch-1` (worktree `WARDEN-hardening`, from `main` at `2452996`).
Runs alongside `feature/group-approvals`; avoids `approvals.py` and `api.py`.

## Progress

- [x] Audit checkpoints (`warden audit head`, `verify --expect`), new module
  `audit_checkpoint.py` so `audit.py` stays untouched.
- [x] `warden test` (policy tests), `examples/policy-tests.json` (18 cases incl. tricks),
  CI step.
- [ ] Coverage-guided fuzzing
- [ ] Release workflow (prepared, not run)
- [ ] Threat model
- [ ] Re-audit of this batch

## Decisions

- **Checkpoints in their own module**: the approvals session may edit `audit.py`.
- **A purged checkpoint fails closed**: an attacker could disguise a rewrite as a
  retention purge, so "can't check" counts as a failure.
- **`head` refuses a broken chain**: saving a checkpoint would bless the tampering.

- **Invalid input in a policy test counts as deny with no rule**, matching what the
  server answers. A broken *policy* is an error (exit 2), never a silent deny-all pass.

## Findings

- Chain hashes don't include any database identity, so two logs with identical rows
  have identical hashes (found while writing a test). Not a weakness for edit
  detection; documented in docs/design/audit-chain.md.

## Blocked / needs Wissam

(none yet)
