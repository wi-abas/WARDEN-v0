# Threat model

Warden is an early-stage, local-first policy checkpoint for AI agent tool calls. It is
**not production-secure**. This page says what it defends, against whom, how each defence
is backed by code and tests, and what it leaves open. Short version: [SECURITY.md](../SECURITY.md).

## What we protect (assets)

| Asset | Why it matters | Where it lives |
|---|---|---|
| **The decision** (allow / deny / require_approval) | The whole point: a wrong `allow` lets an agent act | `engine.py`, `policy.py` |
| **Tool arguments** | May contain secrets, personal data, file contents | Memory only, never logged or stored |
| **Policy file** | Controls every decision | `policies/*.json` (trusted config) |
| **Approvals** | A human's "yes" to one exact action | Memory + state (no arguments) in the audit DB |
| **Audit log** | Evidence of what was decided and approved | SQLite, hash-chained |
| **Agent tokens** | Who an agent is (with `--agents`) | Agents file: SHA-256 hashes, and the keys that prove Warden (mode 600) |
| **Admin key** | Approves actions | `WARDEN_ADMIN_KEY` / printed once |

## Who attacks (and what they can do)

| Attacker | Capability assumed |
|---|---|
| **A1 Hostile or prompt-injected agent** | Sends any request to `/v1/evaluate` or any MCP message through the proxy; chooses every byte of tool names and arguments; retries, races, floods. **The main adversary.** |
| **A2 Other local program / user** | Can reach `127.0.0.1`; may read files that aren't private; can't read Warden's memory unless it runs as the same OS user. |
| **A3 Someone with disk access** | Can edit the audit DB, policy or agents file. |
| **A4 Careless policy author** | Writes rules with typos, loose prefixes, case-sensitive emails. |
| **A5 Malicious MCP server** | The tool itself. Out of scope: Warden decides *whether* to call it, not what it does. |
| **A6 Network attacker** | Out of scope by design: Warden listens on loopback only and refuses foreign `Host` headers. |

## Attacks, defences, evidence

| Attack (by) | Defence | Evidence |
|---|---|---|
| Ask for a forbidden action (A1) | Default deny; most restrictive rule wins; no rule → deny | `tests/test_engine.py`, `tests/test_properties.py` |
| Dodge a rule with path tricks: `..`, `%2e%2e`, `//`, backslashes, edge spaces (A1) | Unclean paths make the request uncheckable → deny | `tests/test_text_tricks.py`, `tests/test_percent_encoding.py`, fuzz target `bypass` |
| Dodge with Unicode: zero-width, right-to-left, full-width, look-alike dots (A1) | Refused in any compared text | `tests/test_unicode_tricks.py` |
| Dodge URL rules: `http://`, ports, case, `user@host`, trailing dot, IDN (A1) | `host_in` compares the parsed host; punycode required | `tests/test_host_in.py`, `tests/test_url_rules.py` |
| Smuggle another protocol or a bad port to an allowed host: `ftp://`, `file://`, `:0`, `:99999`, `:080` (A1) | `host_in` accepts only http/https unless `schemes` says otherwise; bad ports deny the whole request | `tests/test_url_schemes.py` |
| Dodge email rules: lists, display names, case, `%`/`!`/`:` routing (A1) | One plain address only; `ignore_case` | `tests/test_text_tricks.py`, `tests/test_endswith.py` |
| Wrong types (`"500"` vs `500`, `true` vs `1`), missing arguments (A1) | Wrong type → deny; missing → deny/approval rules apply | `tests/test_conditions.py`, `tests/test_model_strictness.py` |
| Smuggle an unchecked argument (`bcc`) (A1) | Tool argument lists | `tests/test_tool_specs.py` |
| Parser differential: duplicate keys, deep nesting, NaN (A1) | Duplicate keys refused (API, proxy, files); deep nesting refused; numbers must be finite | `tests/test_duplicate_request_keys.py`, `tests/test_deep_nesting.py` |
| Replay / modify / race an approval (A1) | Bound to SHA-256 of the exact action and the asking agent; single-use; expires; atomic use | `tests/test_approvals.py`, `tests/test_persistent_approvals.py` |
| Get an action approved blind (an id from an agent's message, a stale list) (A1) | Approving, or rejecting a pending approval, needs the `action_hash` from the list; approving across separate runs warns, and `--yes` needs `--across-runs` | `tests/test_required_action_hash.py`, `tests/test_approval_hygiene.py` |
| Keep asking until a human gives in (A1) | A rejected or revoked action stays refused for `rejection_window_seconds` (default 15 min); only an admin can lift it | `tests/test_sticky_rejections.py` |
| Mislead the approver with hidden characters (A1) | Escaped display + warnings | `tests/test_approval_display.py` |
| Checked ≠ executed (A1) | SDK and proxy run exactly the checked object; proxy forwards re-encoded JSON, refuses extra params and top-level keys, reused ids, batches, unknown methods | `tests/test_sdk.py`, `tests/test_mcp_proxy.py`, `tests/test_mcp_proxy_messages.py`, `tests/test_mcp_proxy_request_ids.py`, fuzz target `proxy` |
| Pretend to be another agent (A1, A2) | Agent tokens (`--agents`): id from a secret, token hashes only (plus the keys that prove Warden), constant-time lookup | `tests/test_agent_tokens.py` |
| Use another agent's permissions (A1) | Per-agent rules (`agents`) need tokens: `serve` refuses a per-agent rule without `--agents` or with an unknown name; most restrictive still wins | `tests/test_per_agent_rules.py` |
| Flood Warden (A1) | 64 KB bodies (counted as received, `Transfer-Encoding` refused); per-agent rate limits and pending-approval caps; capped rejection logging | `tests/test_body_limit.py`, `tests/test_rate_limits.py`, `tests/test_rejection_rate_limit.py` |
| Freeze the server via a locked DB (A2) | Rejection records written in the background | `tests/test_locked_database.py` |
| DNS rebinding from a browser (A6) | `Host` header must be loopback | `tests/test_host_check.py` |
| Rewrite the policy (A2) | `serve` refuses policy and agents files that are group/world-writable, or where the file or any folder/symlink on the path is owned by neither root nor Warden's user, or any folder is group/world-writable without the sticky bit. Not covered: ACLs, changes after startup, Windows | `tests/test_policy_permissions.py` |
| Guess arguments from a copy of the database (A3) | `action_hash` is an HMAC with a per-install key in its own 600 file; `serve` refuses a damaged, shared or symlinked key file | `tests/test_hash_key.py` |
| Edit audit history (A3) | Hash chain; every write read back; triggers and views refused; `audit verify`; checkpoints kept elsewhere catch full rewrites and a cut end | `tests/test_audit_chain.py`, `tests/test_audit_checkpoint.py` |
| Policy typos that silently disable rules (A4) | Invisible/edge-space rule values fail to load; `warden check` warnings W001–W021; `warden test` | `tests/test_policy_typos.py`, `tests/test_check.py`, `tests/test_policy_tests.py` |
| Leak secrets through Warden (A1) | Arguments never logged or stored (crashes log only the error type); errors never echo input | `tests/test_hardening.py`, `tests/test_http_errors.py`, `tests/test_crash_logging.py` |
| Take Warden's port to collect tokens, arguments or the admin key, or to answer allow (A2) | With a token or the admin key: Warden proves itself on that connection before anything secret is sent, and answers are signed (not without `--agents`) | `tests/test_client_proof.py`, `tests/test_server_identity.py`, `tests/test_approvals_cli_proof.py`, `tests/test_mcp_proxy_identity.py` |
| Redirect a client to steal its token (A2) | Clients refuse every redirect | `tests/test_client_redirects.py` |
| Dodge a deny rule with invisible characters (A1) | Default-ignorable characters count as hidden everywhere | `tests/test_default_ignorable.py` |
| Use one approval on two servers, or undo a newer "no" (A1) | Revision-checked updates; the database is the truth | `tests/test_shared_approvals_database.py`, `tests/test_restore_vs_rejection.py` |
| Crash Warden into allowing (A1) | Every error path returns deny | `tests/test_http_errors.py`, fuzz target `http` |

## What stays open (residual risk)

1. **Bypass by not asking (critical, by design).** Warden only decides calls routed
   through it. An agent with direct access to a tool, or a client configured to reach an
   MCP server directly, skips it. Mitigation is deployment: give the agent *only* the
   proxied tools ([mcp-proxy.md](mcp-proxy.md)).
2. **Open mode is the default.** Without `--agents`, any local program can claim any
   `agent_id`, use another agent's approval if it knows the id and the exact action, and
   get fresh rate-limit budgets with new ids.
3. **One shared admin key.** No record of which person approved; anyone with the key
   (or Warden's environment, i.e. the same OS user) can approve.
4. **Same-user compromise.** A2 running as Warden's OS user can read the admin key from
   the process environment, edit the policy, and rewrite the audit DB. File permissions
   don't help within one user.
5. **Audit evidence, not prevention.** Checkpoints only help if kept where A3 can't
   change them. Approval state shares the audit DB file.
6. **Rule expressiveness.** Text checks see text, not meaning (`contains` is a tripwire:
   `rm -fr` slips past `"rm -rf"`, so it's refused in allow rules). Lists inside arguments
   aren't searched; argument lists only cover top-level names.
7. **MCP beyond tools/call.** Server-to-client requests (sampling, elicitation, roots)
   are refused unless the config allows them; once allowed they aren't checked.
   `notifications/*` pass unchecked; resources and prompts need an explicit allow.
8. **Supply chain.** Dependencies are pinned and scanned (`pip-audit`), releases are
   attested ([releasing.md](releasing.md)), but nothing verifies the dependencies' own
   builds.

## Assumptions

- The agent runtime obeys Warden's answer (or uses the SDK / proxy).
- The policy, agents file and admin key are controlled by the operator.
- Warden runs as a different OS user from the agents (recommended, not enforced).
- The clock is roughly right (approval expiry, retention).

## How this is tested

Unit and integration tests for every row above; property-based tests
(`tests/test_properties*.py`); fuzz targets with independent oracles
(`tests/fuzz_targets.py`, weekly Atheris run); mutation testing (`scripts/mutation.py`,
weekly); race tests against a real server; and audits in `docs/security-audit-*.md`.
