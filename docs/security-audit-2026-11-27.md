# Security audit, 2026-11-27 (v0.5.0 review and fixes)

Base: `main` after v0.5.0 (`2ea1da4`). Scope: the whole project after the v0.4.2 field-test
fixes and the v0.5.0 server identity proof. Warden is still an early MVP and **not
production-secure**.

## Method

- A read-through review of the code, docs and tests (an AI reviewer, not an independent
  human audit), checking new findings against the still-open list from the field tests.
- Each finding was reproduced before fixing, where it could be: the `action_hash` brute
  force recovered `amount=48213` from a stored hash in 0.31 seconds.
- Each fix came with regression tests, the full gate (ruff, mypy, 3,200+ tests, coverage
  above 99%), and green CI on Python 3.12 and 3.13 before it was merged. One fix per PR.

## Findings fixed

Severity is for Warden's own threat model (a local checkpoint trusted by its operator).

| # | Severity | Finding | Fix | PR |
|---|---|---|---|---|
| 1 | **Medium** | **`action_hash` revealed guessable arguments.** A plain SHA-256 of the action was stored in every audit row and approval: anyone with a copy of the database could hash likely amounts, recipients or paths and compare. | HMAC-SHA256 with a per-install key in `<audit-db>.hash-key` (mode 600, created once, refused if damaged, shared or a symlink). [design](design/keyed-action-hash.md) | #27 |
| 2 | **Medium** | **Protection was opt-in.** Without `--agents` anyone could claim any agent id and an impostor's `allow` ran tools; the SDK silently dropped to "no token" when `WARDEN_AGENT_TOKEN` was missing. | Agent tokens required by `serve`, the SDK's default client and `warden proxy`, unless `--no-auth` / `WARDEN_NO_AUTH=1` (exactly `1`). [design](design/secure-by-default.md) | #32 |
| 3 | Low (availability) | **A known key id could lock out its owner.** `/v1/hello` was rate limited per key id, and key ids travel in the clear: a program that saw one could use up an agent's or the admin's handshakes, so nobody could approve while it flooded. | Optional `client_mac` (HMAC with the key, bound to the connection and a fresh nonce): only hellos proving the key spend that key's budget; the rest share the unknown budget. | #33 |
| 4 | Low | **`./.env` dodged a deny rule for `.env`.** Rule values without `/` weren't checked as paths. | A compared text that is a path with `.`, `..` or empty segments is uncheckable (deny). | #30 |
| 5 | Low | **MIME encoded-words and `-`/`|` local parts passed email rules.** `=?utf-8?q?evil=40x.com?=@mycompany.com` passed an allow list for `@mycompany.com`. | Refused as not a plain address (deny). | #31 |
| 6 | Usability (fail closed) | **camelCase MCP tools were always denied.** | Tool names may contain uppercase letters, matched case-sensitively; `warden check` W020 warns on case-only differences. | #28 |
| 7 | Policy hygiene | **`amount lte 500` also allowed `-1000000000`, with no warning.** | `warden check` W021. | #29 |

## Still open

The complete list is in [SECURITY.md](../SECURITY.md#what-warden-does-not-protect-against).
From this review:

- **No independent audit and no real users yet.** Everything above was found by the
  project's own (AI-assisted) reviews.
- **PyPI name not claimed.** The trusted publisher isn't set up, so `agent-warden` isn't on
  PyPI and someone else could register it. Install from the repository until then.
- **The identity protocol is Python-only.** Other languages must reimplement it from
  [design/server-identity.md](design/server-identity.md); the fixed test vectors live in
  `tests/test_identity.py`.
- **A backup of the whole data folder holds both the database and the hash key**, which
  together still allow guessing arguments.
- **Paths aren't resolved**: denying exactly `.env` doesn't stop `config/.env`.
