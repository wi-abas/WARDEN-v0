"""The `warden` command.

warden                 start the server (same as `warden serve`)
warden serve           start the server; options: --policy FILE --port N
                       --audit-db FILE --retention-days N (0 = keep forever).
                       Admin key: set WARDEN_ADMIN_KEY (32+ characters).
warden init [FILE]     create a starter policy (default policies/default.json)
warden check FILE      validate a policy file; exit 1 on errors
warden check --strict  ...also exit 1 on warnings (useful in CI)
warden schema          print the JSON Schema for policy files
warden agent add ID     create an agent token (printed once; only its hash is stored)
warden agent list | remove ID     manage the agents file (--agents FILE)
warden audit verify [--audit-db FILE]   check the audit log's hash chain
warden proxy --config FILE
warden proxy [--agent-id ID] [--warden-url URL] [--tool-prefix P] -- COMMAND [ARGS...]
                       run an MCP server behind Warden (see docs/mcp-proxy.md)
"""

import argparse
import json
import os
import sqlite3
import sys
from importlib import resources
from pathlib import Path

from warden import __version__
from warden.agents import (
    DEFAULT_AGENTS_PATH,
    AgentsError,
    add_agent,
    read_agents_file,
    remove_agent,
)
from warden.audit import DEFAULT_AUDIT_PATH, verify_chain
from warden.check import check_policy, format_report
from warden.policy import DEFAULT_POLICY_PATH, Policy
from warden.settings import SettingsError, resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"warden {__version__}")
    commands = parser.add_subparsers(dest="command")
    serve_parser = commands.add_parser("serve", help="start the server")
    serve_parser.add_argument("--policy", help="policy file (env WARDEN_POLICY)")
    serve_parser.add_argument("--port", help="port, default 8000 (env WARDEN_PORT)")
    serve_parser.add_argument("--audit-db", help="audit database file (env WARDEN_AUDIT_DB)")
    serve_parser.add_argument(
        "--retention-days",
        help="days to keep audit entries, 0 = forever (env WARDEN_RETENTION_DAYS)",
    )
    serve_parser.add_argument("--agents", help="agent tokens file (env WARDEN_AGENTS)")
    agent = commands.add_parser("agent", help="manage agent tokens")
    agent.add_argument("action", choices=["add", "list", "remove"])
    agent.add_argument("agent_id", nargs="?")
    agent.add_argument("--agents", type=Path, default=DEFAULT_AGENTS_PATH, help="agents file")
    audit_parser = commands.add_parser("audit", help="audit log tools")
    audit_parser.add_argument("action", choices=["verify"])
    audit_parser.add_argument(
        "--audit-db", type=Path, help="default WARDEN_AUDIT_DB or warden-audit.db"
    )
    init = commands.add_parser("init", help="create a starter policy file")
    init.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    commands.add_parser("schema", help="print the JSON Schema for policy files")
    check = commands.add_parser("check", help="validate a policy file")
    check.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    check.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    proxy = commands.add_parser("proxy", help="run an MCP server behind Warden")
    proxy.add_argument("--config", type=Path, help="proxy config file (JSON)")
    proxy.add_argument("--warden-url", help="default http://127.0.0.1:8000")
    proxy.add_argument("--agent-id", help="agent id sent to Warden (default mcp-proxy)")
    proxy.add_argument("--tool-prefix", help='put in front of tool names, e.g. "github."')
    proxy.add_argument("--approval", choices=["wait", "error"], help="default wait")
    proxy.add_argument("server", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    args = parser.parse_args(argv)

    if args.command == "proxy":
        return run_proxy(args)

    if args.command == "audit":
        path = args.audit_db or Path(os.environ.get("WARDEN_AUDIT_DB") or DEFAULT_AUDIT_PATH)
        return verify_audit(path)

    if args.command == "agent":
        return manage_agents(args.action, args.agent_id, args.agents)

    if args.command == "schema":
        print(policy_schema(), end="")
        return 0

    if args.command == "init":
        return init_policy(args.policy)

    if args.command == "check":
        report = check_policy(args.policy)
        print(format_report(args.policy, report))
        return 1 if report.errors or (args.strict and report.warnings) else 0

    try:
        settings = resolve(
            policy=getattr(args, "policy", None),
            port=getattr(args, "port", None),
            audit_db=getattr(args, "audit_db", None),
            retention_days=getattr(args, "retention_days", None),
            agents=getattr(args, "agents", None),
            env=os.environ,
        )
    except SettingsError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2

    # A broken or empty policy would make the server deny everything. That's safe, but
    # almost certainly a mistake: refuse to start and say why instead.
    report = check_policy(settings.policy)
    if report.errors or report.rules == 0:
        print(format_report(settings.policy, report), file=sys.stderr)
        print("warden: not starting: fix the policy file first", file=sys.stderr)
        return 2

    from warden.api import StartupError  # imported here: `check` never loads the server
    from warden.api import main as serve

    try:
        serve(settings)
    except StartupError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    return 0


def verify_audit(path: Path) -> int:
    """`warden audit verify`: 0 intact, 1 broken, 2 can't read."""
    if not path.is_file():
        print(f"warden: no audit database at {path}", file=sys.stderr)
        return 2
    try:
        report = verify_chain(path)
    except sqlite3.Error as exc:
        print(f"warden: can't read {path}: {type(exc).__name__}", file=sys.stderr)
        return 2
    for table in report.checked:
        line = f"{table}: {report.checked[table]} rows verified"
        if report.unchained[table]:
            line += f", {report.unchained[table]} older rows from before the hash chain"
        print(line)
    if not report.ok:
        for problem in report.problems:
            print(f"BROKEN: {problem}")
        return 1
    print("OK: the hash chain is intact.")
    print("Newest hashes (keep a copy elsewhere to detect a rewrite of the whole log):")
    for table, head in report.heads.items():
        print(f"  {table}: {head}")
    return 0


def manage_agents(action: str, agent_id: str | None, path: Path) -> int:
    """`warden agent add|list|remove`. Tokens are printed once and never stored."""
    try:
        if action == "list":
            agents = read_agents_file(path).agents if path.exists() else ()
            for entry in agents:
                print(entry.id)
            print(f"{len(agents)} agents in {path}", file=sys.stderr)
            return 0
        if not agent_id:
            print(f"warden: `warden agent {action}` needs an agent id", file=sys.stderr)
            return 2
        if action == "remove":
            if not remove_agent(path, agent_id):
                print(f"warden: no agent {agent_id!r} in {path}", file=sys.stderr)
                return 1
            print(f"Removed {agent_id}. Restart Warden for it to take effect.", file=sys.stderr)
            return 0
        token = add_agent(path, agent_id)
    except AgentsError as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 2
    print(f"Added {agent_id} to {path}. Its token (shown ONCE, store it safely):", file=sys.stderr)
    print(token)  # stdout alone, so it can be captured: TOKEN=$(warden agent add x)
    print(
        "Give it to the agent as WARDEN_AGENT_TOKEN, and start Warden with "
        f"--agents {path} (restart if running).",
        file=sys.stderr,
    )
    return 0


def run_proxy(args: argparse.Namespace) -> int:
    """`warden proxy`: config file and/or flags, then relay stdin/stdout until done."""
    import logging

    from warden.mcp_proxy import ConfigError, ProxyConfig, load_config, serve_stdio

    # stdout carries the MCP protocol: every human-readable line goes to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="warden proxy: %(message)s")
    server = args.server[1:] if args.server[:1] == ["--"] else args.server
    try:
        data = load_config(args.config).model_dump() if args.config else {}
        overrides = {
            "warden_url": args.warden_url,
            "agent_id": args.agent_id,
            "tool_prefix": args.tool_prefix,
        }
        data.update({k: v for k, v in overrides.items() if v is not None})
        if args.approval:
            data["approval"] = {**data.get("approval", {}), "mode": args.approval}
        if server:
            data["server"] = {**data.get("server", {}), "command": server[0], "args": server[1:]}
        if "server" not in data:
            raise ConfigError("no MCP server given: use --config FILE or -- COMMAND [ARGS...]")
        config = ProxyConfig.model_validate(data, strict=False)
    except ConfigError as exc:
        print(f"warden proxy: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:  # pydantic's ValidationError is a ValueError
        print(f"warden proxy: invalid settings ({_first_line(exc)})", file=sys.stderr)
        return 2
    return serve_stdio(config)


def _first_line(exc: Exception) -> str:
    from pydantic import ValidationError

    from warden.policy import describe_errors

    if isinstance(exc, ValidationError):
        return "; ".join(describe_errors(exc))
    return type(exc).__name__


def init_policy(path: Path) -> int:
    """Write the starter policy to `path`. Never overwrites an existing file."""
    if path.exists():
        print(f"warden: {path} already exists, not overwriting it", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(starter_policy(), encoding="utf-8")
    path.chmod(0o644)  # others may read, only you may change it (serve refuses otherwise)
    print(f"Created {path}. Next:")
    print("  1. Edit it to describe your agent's tools and rules")
    print(f"  2. uv run warden check {path}")
    print("  3. uv run warden")
    return 0


def policy_schema() -> str:
    schema = Policy.model_json_schema(by_alias=True)
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def starter_policy() -> str:
    return resources.files("warden").joinpath("starter_policy.json").read_text(encoding="utf-8")


def run() -> None:
    sys.exit(main())
