# Design: URL schemes and ports in `host_in`

## Problem

`host_in` compares the URL's real host and ignores everything else, including the
scheme. `allow fetch when url host_in [api.example.com]` also allows
`ftp://api.example.com/`, `gopher://api.example.com:25/...` (a classic way to talk to a
mail server through a "web" tool) or `file://api.example.com/etc/passwd` (some
libraries ignore the host of a `file:` URL and read the local file). Ports are only
checked to be digits: `https://api.example.com:99999/` or `:0` pass, and libraries
disagree about what such a URL reaches (error, truncated, default port).

## Approach

- **`host_in` accepts only `http` and `https` by default** (compared lower-case:
  schemes ignore case). A URL with another scheme can't be checked by this condition:
  it is **uncheckable, and the whole request is denied**, like other URL tricks. Not
  "condition false": for a deny rule, false would let `ftp://evil.net` dodge it and
  land on a looser rule.
- **Opt-in for other schemes**: `"schemes": ["https", "wss"]` on a `host_in`
  condition is the full list it accepts (it replaces the default, so `["https"]` also
  refuses plain `http`). 1 to 10 entries, lower-case, `^[a-z][a-z0-9+.-]{0,31}$`.
  `schemes` on any other op is a load error.
- **Ports**: every URL-shaped check (`host_in` and text ops on URLs, via
  `_is_clean_url`) refuses a port outside 1 to 65535 or with a leading zero
  (`:0443`). An empty port (`host:`) is already refused. Refused = uncheckable =
  whole request denied.
- **`warden check`** W017: two `host_in` conditions on the same argument of the same
  tool accept different schemes. Every rule for a tool is evaluated, so a URL outside
  either list makes that rule's condition uncheckable and denies the whole request,
  even if the other rule would allow it. Usually not what was meant; use the same
  `schemes` everywhere.
- Schema stays `policy-v1` (`schemes` is a new optional field).

## Breaking-change notes (v0.4)

- A `host_in` rule that used to match `ftp://`, `ws://`, `git://` etc. now denies
  those requests. Add `schemes` to the condition if the tool really needs them. Run
  `warden test` with such URLs before upgrading.
- URLs with ports like `:0`, `:99999` or `:080` are now denied wherever a rule
  compares URLs.
- CHANGELOG "Breaking"; docs/policies.md `host_in` section.

## Also: `warden proxy` reads `WARDEN_URL`

Today `warden approvals` and the SDK read `WARDEN_URL`, but `warden proxy` doesn't
(docs/api.md calls this out), so one exported variable points two tools at one Warden
and the proxy at another. Fix: the proxy uses `--warden-url`, then `warden_url` in the
config file, then `WARDEN_URL`, then the default. The config file comes before the
environment because it's the specific, reviewed setting for this proxy, and so existing
configs keep their meaning. `check_url` still applies (local http only), and the proxy
already keeps `WARDEN_*` secrets out of the MCP server's environment (the URL isn't one).

## Threat model

Protects against: reaching a non-web protocol through a `host_in` allow rule (ftp,
gopher, file, ...); dodging a `host_in` deny rule with an odd scheme; port values that
different libraries read differently.

## What it doesn't cover

- IP addresses written oddly (`http://2130706433/`, `http://0x7f.1/`) still aren't
  recognised as `127.0.0.1` (see SECURITY.md): allow lists, not deny lists, for hosts.
- DNS: `api.example.com` can resolve anywhere, including `127.0.0.1`. Warden checks
  names, not where they lead.
- Text ops (`startswith "https://..."`) already check the scheme as text; they don't get
  `schemes`.
- **Open question for Wissam:** should a non-http(s) scheme be uncheckable (deny the
  request, this note) for **allow** rules too, or simply not match there (then a
  different allow rule for the same tool could still allow it)? Uncheckable is
  stricter and the same for every effect.
