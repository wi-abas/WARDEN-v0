# Design: Python SDK (`warden.sdk`)

## Problem

Asking Warden by hand is easy to get subtly wrong: run the tool on anything but
`allow`, check one dict and run with another (or with the same dict after something
changed it), forget the approval retry, or treat "Warden down" as "go ahead".

## Approach

```python
from warden.sdk import WardenClient, guard

warden = WardenClient(agent_id="billing-agent")


@guard(client=warden, wait_for_approval=120)
def send_invoice(to: str, amount: int) -> str: ...


send_invoice(to="acme", amount=200)  # runs only if Warden says allow
```

- **Freeze**: the call's arguments are bound to parameter names (defaults applied, so
  Warden sees the full effective call), then copied through JSON once. That copy is what
  Warden checks **and** what the function receives. Later changes to the caller's
  objects can't reach the tool (no time-of-check / time-of-use gap). Values that aren't
  plain JSON (objects, sets, NaN) can't be checked, so the call is refused.
- **Fail closed**: anything but `allow` raises `NotAllowed` (with Warden's reason) and the
  function doesn't run. Warden unreachable or a bad answer is a deny (`WardenClient`).
- **Approvals**: on `require_approval` the SDK immediately re-asks with the `approval_id`
  (a human may already have approved this exact action). Then it either raises
  `ApprovalPending` (default) or polls until allow / deny / timeout
  (`wait_for_approval=seconds`).
- `async def` tools are supported; the HTTP call runs in a thread.
- `run_guarded(tool, arguments, fn)` does the same without a decorator.

## Threat model

Protects against: running a tool after a non-allow answer, checked ≠ executed
arguments (mutation after the check, including nested lists/dicts and from other
threads), Warden outages, approval mix-ups (the approval is bound to the frozen action).

## What it doesn't cover

- Code that calls the undecorated function, or the underlying API directly.
- What the tool does with its arguments (e.g. a path that is a symlink).
- Positional-only and `*args` parameters: refused at decoration time (they can't be
  named for the policy).
- Tools receive JSON-shaped copies: tuples arrive as lists, dict keys as strings.
