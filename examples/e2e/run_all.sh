#!/usr/bin/env bash
# End-to-end scenario: a real Warden server, fake agents, a fake MCP server behind
# `warden proxy`, a pretend human, a restart, and audit checks. See README.md.
#
# Usage: bash examples/e2e/run_all.sh
# Exit code 0 only if every check passed. All state (agent tokens, admin key, audit
# database, logs) lives in a fresh temp folder that is deleted at the end, and every
# process started here is stopped, even on failure or Ctrl-C.
# Set E2E_PYTHON to a Python that has Warden installed to skip `uv run`; set
# E2E_KEEP=1 to keep the temp folder for debugging.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
if [ -n "${E2E_PYTHON:-}" ]; then
  PY="$E2E_PYTHON"
else
  PY="$(cd "$REPO" && uv run --quiet python -c 'import sys; print(sys.executable)')" || exit 2
fi
WARDEN="$(dirname "$PY")/warden"
[ -x "$WARDEN" ] || { echo "warden not found next to $PY (run uv sync)"; exit 2; }

STATE="$(mktemp -d "${TMPDIR:-/tmp}/warden-e2e.XXXXXX")"
LOG="$STATE/run.log"
SERVER_PID=""
START=$(date +%s)

stop_server() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
  fi
}
cleanup() {
  stop_server
  # Anything else still running from this script (e.g. a proxy left by a crashed step).
  for pid in $(jobs -p); do kill "$pid" 2>/dev/null; done
  if [ "${E2E_KEEP:-0}" = 1 ]; then echo "state kept in $STATE"; else rm -rf "$STATE"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

free_port() {
  "$PY" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
PORT=$(free_port)
DEAD_PORT=$(free_port)  # nothing listens here: the client must fail closed

# Fresh secrets for this run only (never written outside $STATE).
export WARDEN_ADMIN_KEY="$("$PY" -c 'import secrets; print(secrets.token_hex(32))')"
export WARDEN_URL="http://127.0.0.1:$PORT"
export E2E_STATE="$STATE" E2E_PORT="$PORT" E2E_DEAD_PORT="$DEAD_PORT" E2E_WARDEN="$WARDEN"
export PYTHONDONTWRITEBYTECODE=1
cp "$HERE/policy.json" "$STATE/policy.json"

header() { printf '\n==== %s\n' "$*" | tee -a "$LOG"; }

# check NAME COMMAND... : PASS if the command exits 0 (its output goes to the log only).
check() {
  local name="$1"; shift
  if "$@" >>"$LOG" 2>&1; then echo "PASS  $name" | tee -a "$LOG"
  else echo "FAIL  $name" | tee -a "$LOG"; fi
}
# check_exit NAME CODE COMMAND... : PASS if the command exits with exactly CODE.
check_exit() {
  local name="$1" want="$2"; shift 2
  "$@" >>"$LOG" 2>&1
  local got=$?
  if [ "$got" = "$want" ]; then echo "PASS  $name" | tee -a "$LOG"
  else echo "FAIL  $name  -> exit $got, expected $want" | tee -a "$LOG"; fi
}
# step SCRIPT ARGS... : run one Python step; its PASS/FAIL lines are shown and logged.
step() {
  "$PY" "$HERE/$1" "${@:2}" 2>&1 | tee -a "$LOG"
  local code=${PIPESTATUS[0]}
  [ "$code" = 0 ] || echo "FAIL  $* crashed (exit $code)" | tee -a "$LOG"
}
pending() { "$PY" "$HERE/e2e_common.py" pending "$@"; }
w() { "$WARDEN" "$@"; }

start_server() {
  # The warden binary directly (not the w function), so $! is the server itself.
  "$WARDEN" serve --policy "$STATE/policy.json" --port "$PORT" --audit-db "$STATE/audit.db" \
    --agents "$STATE/agents.json" >>"$STATE/warden.log" 2>&1 &
  SERVER_PID=$!
  sleep 0.2
  for _ in $(seq 1 100); do
    if "$PY" -c "import urllib.request as u; u.urlopen('$WARDEN_URL/health', timeout=1)" 2>/dev/null
    then return 0; fi
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.1
  done
  echo "FAIL  Warden did not start (see warden.log)" | tee -a "$LOG"
  cat "$STATE/warden.log"
  return 1
}

header "1. policy"
check "policy passes warden check --strict" w check "$STATE/policy.json" --strict
check "policy tests pass" w test "$HERE/policy-tests.json" --policy "$STATE/policy.json"

header "2. agents and server"
for agent in good-agent sneaky-agent flood-bot mcp-desktop; do
  w agent add "$agent" --agents "$STATE/agents.json" 2>>"$LOG" | tail -1 >"$STATE/token-$agent"
done
check "4 agent tokens created" test "$(cat "$STATE"/token-* | grep -c '^wdn_')" = 4
check "policy agent names match the agents file" w check "$STATE/policy.json" --strict --agents "$STATE/agents.json"
start_server || exit 1
echo "Warden on port $PORT"

# Proxy configs: the fake MCP server runs with this Python and logs what it receives.
for mode in error wait; do
  timeout=3; [ "$mode" = error ] && timeout=10
  cat >"$STATE/proxy-$mode.json" <<EOF
{
  "warden_url": "$WARDEN_URL",
  "agent_id": "mcp-desktop",
  "tool_prefix": "fs.",
  "server": {"command": "$PY", "args": ["$HERE/e2e_mcp_server.py", "$STATE/mcp-server-received.log"]},
  "approval": {"mode": "$mode", "timeout_seconds": $timeout, "poll_seconds": 0.2},
  "allow_server_requests": ["roots/list"]
}
EOF
done

header "3. well-behaved agent (client + @guard)"
step good_agent.py first
header "3b. the human approves the delete and rejects the email (warden approvals CLI)"
check "CLI: list pending approvals" w approvals list --group
check "CLI: approve the delete" w approvals approve $(pending good-agent delete_file) --yes
check "CLI: reject the email" w approvals reject $(pending good-agent send_email) --yes
step good_agent.py retry
header "3b2. sticky rejection: the human lifts it, the agent may ask again"
rejected() { "$PY" "$HERE/e2e_common.py" rejected "$@"; }
check "CLI: list standing rejections" w approvals list --rejected
check "CLI: lift the email rejection" w approvals lift $(rejected good-agent send_email) --yes
step good_agent.py ask_again
header "3c. group decisions are all or nothing"
deletes=($(pending good-agent delete_file))
emails=($(pending good-agent send_email))
check_exit "CLI: a group mixing two tools is refused" 1 \
  w approvals approve "${deletes[0]}" "${emails[0]}" --yes
check_exit "CLI: an id listed twice is refused" 2 \
  w approvals approve "${deletes[0]}" "${deletes[0]}" --yes
check_exit "CLI: approve one tool's group" 0 w approvals approve "${deletes[@]}" --yes

header "4. sneaky agent: raw HTTP bypass attempts"
step sneaky_agent.py
header "4b. sneaky agent: approvals, admin endpoints, sizes"
step sneaky_approvals.py
header "4c. flood"
step flood.py

header "5. MCP proxy (error mode)"
step mcp_client.py main
check "CLI: approve the MCP write" w approvals approve $(pending mcp-desktop fs.write_file) --yes
step mcp_client.py retry
step mcp_client.py loginject
header "5b. MCP proxy (wait mode)"
step mcp_client.py wait
step mcp_client.py server

header "6. SDK wait_for_approval"
step sdk_wait.py

header "7. restart with a pending approval"
step restart.py before
stop_server
start_server || exit 1
step restart.py after
stop_server

header "8. audit log"
DB="$STATE/audit.db"
check "audit verify" w audit verify --audit-db "$DB"
w audit head --audit-db "$DB" >"$STATE/checkpoint.json" 2>>"$LOG"
check "audit verify --expect checkpoint" w audit verify --audit-db "$DB" --expect "$STATE/checkpoint.json"
"$PY" "$HERE/tamper.py" "$DB" "$STATE/flipped.db" flip
check_exit "a changed row is detected" 1 w audit verify --audit-db "$STATE/flipped.db"
"$PY" "$HERE/tamper.py" "$DB" "$STATE/truncated.db" truncate
check_exit "a cut-off newest row is detected by the checkpoint" 1 \
  w audit verify --audit-db "$STATE/truncated.db" --expect "$STATE/checkpoint.json"
rm -f "$STATE"/flipped.db* "$STATE"/truncated.db*

header "9. no arguments or secrets in the audit database or logs"
secrets=(GOODSECRET SNEAKYSECRET MCPSECRET RESTARTSECRET WAIT-approved WAIT-timeout /workspace/
  "$WARDEN_ADMIN_KEY")
for agent in good-agent sneaky-agent flood-bot mcp-desktop; do secrets+=("$(cat "$STATE/token-$agent")"); done
files=("$STATE"/audit.db* "$STATE/warden.log" "$STATE"/proxy-stderr-*.log)
for secret in "${secrets[@]}"; do
  label="$secret"; case "$secret" in wdn_*) label="an agent token";; "$WARDEN_ADMIN_KEY") label="the admin key";; esac
  check "'$label' not in the audit database or logs" bash -c '! grep -a -q -F -- "$0" "${@}"' "$secret" "${files[@]}"
done

header "SUMMARY"
PASSED=$(grep -c '^PASS ' "$LOG")
FAILED=$(grep -c '^FAIL ' "$LOG")
if [ "$FAILED" != 0 ]; then
  echo "Failed checks:"
  grep '^FAIL ' "$LOG" | sed 's/^/  /'
fi
echo "RESULT: $PASSED passed, $FAILED failed ($(( $(date +%s) - START ))s)"
[ "$FAILED" = 0 ] && [ "$PASSED" -gt 0 ]
