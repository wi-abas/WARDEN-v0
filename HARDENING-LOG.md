# Hardening log: batch 1

Branch `hardening/batch-1` (worktree `WARDEN-hardening`, from `main` at `2452996`).
Runs alongside `feature/group-approvals`; avoids `approvals.py` and `api.py`.

## Progress

- [x] Audit checkpoints (`warden audit head`, `verify --expect`), new module
  `audit_checkpoint.py` so `audit.py` stays untouched.
- [x] `warden test` (policy tests), `examples/policy-tests.json` (18 cases incl. tricks),
  CI step.
- [x] Fix: deeply nested JSON (found while preparing fuzzing)
- [x] Stricter email check (found by fuzzing)
- [x] Coverage-guided fuzzing: 5 targets, Hypothesis in every run, Atheris weekly in CI
- [x] Release workflow (prepared, not run): `.github/workflows/release.yml`, `docs/releasing.md`
- [ ] Threat model
- [ ] Re-audit of this batch

## Decisions

- **Checkpoints in their own module**: the approvals session may edit `audit.py`.
- **A purged checkpoint fails closed**: an attacker could disguise a rewrite as a
  retention purge, so "can't check" counts as a failure.
- **`head` refuses a broken chain**: saving a checkpoint would bless the tampering.

- **Invalid input in a policy test counts as deny with no rule**, matching what the
  server answers. A broken *policy* is an error (exit 2), never a silent deny-all pass.

- **Atheris as a Linux-only dependency group** (`fuzz`, `atheris==3.1.0; sys_platform ==
  'linux'`), so it's hash-locked in uv.lock but never installed on macOS or for users.
  It can't build on macOS (needs a libFuzzer clang), so the Atheris runner itself was
  NOT run locally; the targets were (100,000 inputs through Hypothesis, clean). The
  weekly workflow is the first real Atheris run: check it once.

- **Release: two jobs.** Build (read-only, runs our code and tests) is separate from
  publish (OIDC token only there, behind a reviewer-protected environment). uv's own
  `uv publish --trusted-publishing always` instead of a third-party publish action;
  SBOM from `uv export --format cyclonedx1.5` (experimental in uv 0.13, pinned by the
  setup-uv version). Action SHAs looked up from the GitHub API; all releases > 2 weeks old.
  The workflow doesn't create GitHub releases (no write permission needed).

## Findings

- **Deeply nested JSON (found while preparing the fuzz targets).** Python's json.loads
  raises RecursionError (not a ValueError) on input like 30,000 nested brackets, which
  fits easily in the 64 KB body limit. Effects: the API answered 500 "internal error"
  (still deny, server stayed up); **one such line ended a whole MCP proxy session**
  (availability: a prompt-injected model could cut off all tools; nothing unchecked was
  forwarded); `warden check`, `audit verify`, the SDK and config readers crashed with a
  traceback. Fixed at all 11 parse sites; 14 regression tests (10 fail without the fix).
  Touches api.py (one except clause in DuplicateKeyCheck), kept minimal to avoid
  conflicts with the group-approvals branch.
- Chain hashes don't include any database identity, so two logs with identical rows
  have identical hashes (found while writing a test). Not a weakness for edit
  detection; documented in docs/design/audit-chain.md.

- **Email routing tricks passed email rules (found by the bypass fuzz target).**
  `_is_plain_email` refused spaces, lists, quotes and brackets but not `%` (the
  "percent hack": `user%evil.net@example.com` is relayed to evil.net by some MTAs), `!`
  (UUCP bang paths), `:` (group / source-route syntax), `\`, an empty local part, or
  stray dots. An allow rule `endswith "@example.com"` allowed them. Modern MTAs mostly
  ignore these, but Warden can't know the tool's mail stack. Now refused (stricter
  only); 16 tests. Legit addresses (dots, `+tags`, non-English names) still pass.
- **Fuzz oracle false alarms, investigated and not bugs**: a non-ASCII name before the
  `@` (SMTPUTF8), a non-ASCII URL fragment, unassigned code points in a path, and
  canonical combining characters. None move a path out of /workspace/, change a URL
  host or an email domain. The oracles were narrowed to the real invariant.

## Blocked / needs Wissam

- **Release setup by hand** (docs/releasing.md): add the PyPI trusted publisher
  (repo wi-abas/agent-warden, workflow release.yml, environment pypi), create the
  `pypi` environment in GitHub with yourself as required reviewer, optionally protect
  `v*` tags. Until then a tag push fails at the publish step (safe).
- **First Atheris run**: trigger "Fuzzing" once by hand (Actions > Fuzzing > Run
  workflow) to confirm it installs and runs on Linux; it couldn't be run on macOS.
