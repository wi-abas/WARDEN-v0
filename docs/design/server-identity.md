# Design: proving that Warden is Warden (built: option 1)

## Problem

Without this, clients trust whatever listens on Warden's URL. If Warden is stopped and another local
program listens on port 8000, it receives the agent token and the tool arguments, and its
`allow` makes the tool run. `warden approvals` has the same problem with the admin key.
Agent tokens prove the agent to Warden; nothing proves Warden to the agent.

Two goals: an answer only counts if it comes from Warden, **and** secrets (token, admin key,
arguments) are only sent after Warden has proven itself. Signing the answer alone gives
only the first.

## A constraint: the server stores only token hashes

`warden-agents.json` holds `SHA-256(token)`, so the server can't compute
`HMAC(token, ...)`. The hash itself could be the key (the client can compute it), but then
anyone who reads the agents file can play both sides. Any HMAC scheme needs a key the
server can read, and a file holding it is a real secret, unlike today. A public-key
signature would avoid that, but the standard library has none (new dependency).

## Options

1. **HMAC challenge with a key per agent.** Works over the present HTTP and on every OS.
   Doesn't encrypt. The agents file becomes secret.
2. **Unix domain socket**, in a folder only its owner can enter, with owner and mode checked
   by the client. No keys and no port to take. Doesn't cover other programs of the same OS
   user (the usual case: they can replace the socket), Windows, plain-HTTP clients or the
   `/docs` page. Clients and settings need a second transport.
3. **Supervised port** (launchd/systemd holds it, also while Warden restarts). No protocol
   change, but needs per-OS setup, proves nothing to the client, and fails when the
   supervisor isn't running. An extra, not a fix.

**Recommendation: option 1.** It is the only one that also stops a same-user program that
has only taken the port.

## Protocol (option 1)

All strings ASCII, all hashes SHA-256, hex lowercase.

Keys:

- Per agent: `K = HMAC-SHA256(key=token, msg="warden-server-identity-v1")`. The client
  derives it from its token; `warden agent add` stores it while it still has the token.
- Admin: the same formula with the admin key (the server has it).
- `key_id = hex(SHA256("warden-key-id-v1\n" + K))[:32]`: says which key, reveals nothing.

Steps, on **one** TCP connection (`http.client`, `auto_open = 0` so it can't reconnect):

1. The client connects and reads the peer's numeric address from the socket
   (`getpeername`): `addr = "127.0.0.1:8000"` (or `"[::1]:8000"`), and its own
   (`getsockname`): `caddr = "127.0.0.1:54321"`.
2. Client: `POST /v1/hello` with `{"key_id": ..., "nonce": N, "client_mac": C}`, `N` = 32
   random bytes as hex, fresh for every question, and
   `C = hex(HMAC(K, "warden-client-hello-v1\n" + N + "\n" + addr + "\n" + caddr))`
   (optional; it only decides which budget the hello counts against, see below).
   No token, no arguments.
3. Server: `{"mac": hex(HMAC(K, "warden-hello-v1\n" + N + "\n" + addr + "\n" + caddr))}`.
   Here `addr` is the server's **own** socket address (ASGI `scope["server"]`) and `caddr`
   its peer (`scope["client"]`), never a header. Unknown `key_id`: 401.
4. The client compares with `hmac.compare_digest`. Mismatch: close, nothing more is sent.
5. Client: `POST /v1/evaluate` as today (bearer token included), plus the header
   `Warden-Nonce: N`.
6. Server: answers as today, plus the header `Warden-Mac: hex(HMAC(K, M))`, where
   `M = "warden-answer-v1\n" + N + "\n" + addr + "\n" + caddr + "\n" + method + "\n" +
   hex(path_and_query) + "\n" + hex(SHA256(request body)) + "\n" + status + "\n" + hex(Retry-After or "") + "\n" +
   hex(SHA256(response body))`, over the exact bytes.
7. The client checks the MAC over the bytes it sent and received **before** parsing. Only
   then does the answer (also its `Retry-After`) count.

Admin endpoints use the same steps with the admin key's `K`.
Why `addr` is signed: an impostor on 8000 could otherwise pass the hello on to a Warden on
another port. Why `caddr` is signed too: see below. Why the request is signed: an `allow` for one action can't be used for
another. Why `N` is fresh: old answers can't be replayed. The labels keep a hello MAC
from being an answer MAC.

**`caddr` (a flaw in the first version of this note).** The server's address alone isn't
enough. An impostor takes a connection while Warden is down, frees the port at once, waits
until Warden runs on that same port, and passes the hello on: `addr` is the same. With
`caddr` in the MAC, Warden signs the impostor's own client address, which can't be the
victim's: that connection exists. Uvicorn by default takes the client address from
`X-Forwarded-For` (with a port), which the impostor could write, so `serve` turns that off,
and a request with that header gets no proof and no signature (400), however Warden is run.

**What is signed.** Every answer to a request with exactly one valid `Warden-Nonce` and
exactly one valid secret for that path, also 4xx/5xx and refusals by middleware. Not
signed, so denied by the client: an answer given before the whole body was read (411, 413,
a foreign `Host`), Uvicorn's own 400, and a crash while signing. The body limit still
counts every byte that arrives; the signer only hashes them in passing.

**Timeout.** One deadline covers connecting, hello and question (single bytes don't extend
it). No proof in time: "couldn't prove". After the proof, a timeout or lost connection is
`unreachable`, as before: that connection was Warden's, and it never allows.

**Hello budgets.** `hello` has the host check and body limit of the other endpoints. A hello
with a valid `client_mac` (the caller holds K) counts against that key's own budget (6,000
per minute, or four times the agent's request limit if that is more: an agent over its limit
must still get its signed 429). Every other hello (unknown `key_id`, no `client_mac`, a wrong
one, one made for another connection, or a nonce already used with one in the last minute)
counts against a shared budget for unknown callers (600 per minute). Key ids are sent in
the clear, so before this a program that was an impostor once could use up that agent's (or
the admin's) hellos; now it only uses up the shared budget. The server remembers the nonces
of the last minute that came with a valid `client_mac` (at most 200,000; when full, hellos
count as unknown). `client_mac` never changes the answer: a hello without one is answered
the same way, so plain HTTP clients keep working, sharing the unknown budget. It reveals
nothing about K, and a relayed one doesn't match the relay's connection.

**Not an oracle.** Anyone who knows a `key_id` can have MACs made, but only for the
caller's own connection, and with the hello label. `key_id`s are looked up by comparing all
of them in constant time. Nonces and MACs are in bodies and headers, so never in the access
log. The token must belong to the agent whose `K` signs the answer: after the
token check, the server takes `K` from the authenticated agent.

## Where the secrets live, and setup

| Side | Secret | Where |
|---|---|---|
| Agent | token (`K` derived in memory) | `WARDEN_AGENT_TOKEN`, as today |
| Server | `token_sha256` and `server_key` (K) per agent | agents file, mode 600 |
| `warden approvals` and server | admin key | `WARDEN_ADMIN_KEY`, as today |

```sh
warden agent add billing-agent      # also writes server_key; prints the token once
export WARDEN_AGENT_TOKEN=wdn_...   # nothing else to copy to the client
```

`server_key` is required: an agents file without it refuses to start, naming the agents to
delete and add again (the key can't be computed from the hash). `warden serve` also
refuses an agents file that group or others can **read** (not only write). Rotating a
token rotates `K`. The token is still sent in step 5, so a stolen agents file lets someone
imitate Warden, but not the agent.

## Fail closed

- A client with a token or admin key **always** demands proof: no flag, environment variable
  or server answer turns that off. Server without `/v1/hello`, 401, wrong, missing or
  repeated MAC, malformed hex, redirect, extra connection, timeout: DENY "Warden couldn't
  prove its identity".
- A failed proof is never retried as unproven, and not as `unreachable` either: a polling
  wait ends with the deny. Connection refused or lost stays `unreachable` (a restart).
- An HTTP error without a valid MAC is a plain deny; its reason and `Retry-After` are ignored.
- `warden approvals` prints nothing from an unproven answer. A hello 401 is "the key is
  wrong, or it isn't Warden": which one can't be known.
- Server: any error while signing means a 500 without a MAC, which the client denies.
  `K` is never logged, shown in a repr or put in an error.

## Without `--agents`

There is no shared secret, so there is nothing to prove with. A client without a token
behaves as today, and SECURITY.md says it trusts the port. Startup already warns that there
are no agent tokens; the warning should name this too. Not inventing a key file read by
default: any program of the same user could read it. A client **with** a token against a
server without `--agents` is denied (unknown `key_id`).

## Threat model

Stops: a program that took Warden's port (or `::1` behind `localhost`), changed or replayed
answers, an answer for another action, relaying to a Warden on another address or (later)
on the same one, downgrade.

Doesn't cover:

- Whoever can read the agents file, the token, the admin key or either process's memory;
  often any program of the same OS user.
- Root, or anyone who can sniff or inject on loopback: there is no encryption.
- Anything between client and Warden that keeps both addresses (firewall rules, as root).
  A forwarder that changes one (`ssh -L`, container port mapping) makes every call denied.
- Clients that don't check (curl, the README's plain-HTTP example, `/docs`, `examples/agent.py`
  without `WARDEN_AGENT_TOKEN`), and everything without `--agents`.
- A guessable `WARDEN_ADMIN_KEY`: `key_id` lets an impostor test guesses offline. Agent
  tokens and the generated admin key are random, so this only concerns a key chosen by hand
  (Warden checks its length, not its randomness).
- Finding out that Warden is expected: an impostor sees the hello (a key id, a nonce).
- A real Warden with a bad policy, or denial of service by taking the port (the result is
  deny).

## Tests

1. Impostor that always answers allow, with a token set: deny, tool not run, and it never
   received the token or any argument (SDK sync, SDK async, proxy).
2. Same for `warden approvals`: the admin key is never sent.
3. Good path over real HTTP: allow, deny, approval wait, 429 with `Retry-After`, 503, restart
   during a wait.
4. MAC failures, each a deny: missing, empty, repeated, uppercase, truncated, one bit changed,
   another agent's key, hello MAC used as answer MAC.
5. Answer replayed from an earlier question (other `N`); answer for other arguments, another
   path, another status; changed body; changed `Retry-After`.
6. Relay to a real Warden on another port; `localhost` where the impostor has `::1`.
7. Connection closed after the hello and the port taken: nothing is sent to the new listener.
8. Downgrade: server without `/v1/hello`, hello 404/401/302/garbage/oversized/slow.
9. Token of agent A with the `key_id` of agent B: the client denies.
10. Agents file without `server_key`, with a malformed one, or readable by others: no start.
    `agent add` writes mode 600; the stored key equals the client's derived key (fixed test
    vector, so both sides can't drift together).
11. Polling: failed proof ends the wait; connection refused doesn't.
12. No token and no `--agents`: unchanged. Token and no `--agents`: deny.
13. `hello`: host check, size limit, duplicate keys, unknown fields, budget.
14. `K`, token and arguments appear in no log, repr, error, audit row or database file.
15. MAC compared with `hmac.compare_digest` (mutation tests on client and signing code).
