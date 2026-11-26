# Design: agent tokens on by default

## Problem

Without `--agents`, any local program can claim any `agent_id`, and a program that takes
Warden's port gets the tool arguments and can answer `allow` (clients can't tell it from
Warden). That mode was the default: `warden serve` only printed a warning. The SDK fell
back to "no token" when `WARDEN_AGENT_TOKEN` wasn't set, so one forgotten environment
variable in a container silently gave the unprotected mode, with nothing printed.
Protection should be the default, and turning it off should take a deliberate step.

## Approach

- **Server.** `warden serve` refuses to start without an agents file (`--agents` /
  `WARDEN_AGENTS`) unless told `--no-auth` (or `WARDEN_NO_AUTH=1`). The error says how
  to make one (`warden agent add NAME`). With `--no-auth` the old warning is printed.
- **SDK.** `default_client()` (used by `@guard` and `run_guarded` when no client is given)
  refuses to build a client without `WARDEN_AGENT_TOKEN` unless `WARDEN_NO_AUTH=1`. The
  error is raised before anything is sent, so the tool doesn't run (fails closed).
  `WardenClient(...)` built in code is unchanged: writing it without a token is an
  explicit choice, visible in the code.
- **MCP proxy.** `warden proxy` refuses to start without `WARDEN_AGENT_TOKEN` unless
  `--no-auth` (or `WARDEN_NO_AUTH=1`).
- One switch name everywhere: `--no-auth` / `WARDEN_NO_AUTH=1`. Only the exact value `1`
  turns it on; any other value is an error (no "false" that quietly means true).

## Threat model

Protects against starting the unprotected mode by accident: a missing flag, or an
environment variable lost between a shell and a container. It doesn't change what the
unprotected mode allows once someone picks it.

## What it doesn't cover

- `--no-auth` is still available, and with it everything in SECURITY.md about the
  self-declared mode applies.
- A `WardenClient` built in code without a token isn't refused.
- Tests and the demo use `--no-auth` / `WARDEN_NO_AUTH=1` where tokens add nothing.
