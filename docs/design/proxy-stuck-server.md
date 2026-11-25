# Design: a server that stops reading, and a client that leaves

## Problem

The proxy read one client message, forwarded it and waited until the server had taken it.
If the server stopped reading its input, the proxy was stuck in that wait and didn't notice
that the client had gone. A call approved meanwhile could still run once the server resumed.

## Approach

- **Reading is its own task.** Lines go into a queue, so the end of input is noticed at
  once, whatever the server does. At most 10,000 lines and 32 MB may wait; more are
  refused (error with id `null`), never forwarded.
- **One message at a time is written** (a fair lock), and the next only starts once the
  previous has fully left the proxy (write buffer limit 0). So later messages wait where
  they can still be dropped.
- **Right before a call that needed an approval is written**, the proxy checks that the
  client is still there. If not, the call is refused.
- **If the client leaves while such a call is being written**, the server's input is cut
  off (aborted): the rest of the line is never sent, and half a JSON line isn't a call.
- **Other messages** may finish after the client left (`printf ... | warden proxy`), but a
  server that takes nothing for 30 seconds is cut off too, so the proxy always ends.
- Cancelling a call only has an effect until it is written.

## Threat model

Protects against a human's approval running a tool for a client that is gone, because the
server was slow, frozen, or deliberately stalling.

## What it doesn't cover

- A call that already left the proxy: it sits in the operating system's pipe (up to 64 KB
  or so) and the server can read it later. It can't be pulled back.
- Calls Warden allows without an approval still run after the client left, as before.
