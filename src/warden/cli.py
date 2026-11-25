"""The `warden` command.

warden                 start the server (same as `warden serve`)
warden serve           start the server; options: --policy FILE --port N
                       --audit-db FILE --retention-days N (0 = keep forever).
                       Admin key: set WARDEN_ADMIN_KEY (32+ characters).
warden init [FILE]     create a starter policy (default policies/default.json)
warden check FILE      validate a policy file; exit 1 on errors
warden check --strict  ...also exit 1 on warnings (useful in CI)
warden check --agents FILE   ...also check the agent names per-agent rules use
warden schema          print the JSON Schema for policy files
warden test FILE [--policy FILE]        run policy tests (example requests + expected decisions)
warden limits [--policy FILE]           show rate limits and approval quotas
warden limits set [--agent ID] [--requests-per-minute N] [--pending N]
warden limits reset [--agent ID]        change them in the policy file
warden agent add ID     create an agent token (printed once; only its hash is stored)
warden agent list | remove ID     manage the agents file (--agents FILE)
warden audit verify [--audit-db FILE] [--expect FILE]   check the audit log's hash chain
warden audit head [--audit-db FILE]     print a checkpoint to keep elsewhere
warden approvals list [--group] [--agent A] [--tool T] [--max-age MIN]  pending, in full
warden approvals approve|reject ID [ID ...] [--yes] [--across-runs]
warden approvals list --rejected / lift ID [--yes]   standing rejections / lift one
                       decide exactly these, all or nothing (needs WARDEN_ADMIN_KEY)
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

from pydantic import ValidationError

from warden import __version__
from warden.agents import (
    DEFAULT_AGENTS_PATH,
    AgentsError,
    add_agent,
    read_agents_file,
    remove_agent,
)
from warden.audit import DEFAULT_AUDIT_PATH, read_error, verify_chain
from warden.check import check_policy, format_report
from warden.policy import DEFAULT_POLICY_PATH, Policy, describe_errors
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
    agent.add_argument(
        "--agents",
        type=Path,
        default=Path(os.environ.get("WARDEN_AGENTS") or DEFAULT_AGENTS_PATH),
        help=f"agents file (default WARDEN_AGENTS or {DEFAULT_AGENTS_PATH})",
    )
    audit_parser = commands.add_parser("audit", help="audit log tools")
    audit_parser.add_argument("action", choices=["verify", "head"])
    audit_parser.add_argument("--expect", type=Path, help="checkpoint file from `audit head`")
    audit_parser.add_argument(
        "--audit-db", type=Path, help="default WARDEN_AUDIT_DB or warden-audit.db"
    )
    approvals = commands.add_parser("approvals", help="review and decide pending approvals")
    approvals.add_argument("action", choices=["list", "approve", "reject", "lift"])
    approvals.add_argument("ids", nargs="*", metavar="ID", help="approval ids")
    approvals.add_argument("--group", action="store_true", help="list: group by agent and tool")
    approvals.add_argument(
        "--rejected", action="store_true", help="list: rejections that still stand"
    )
    approvals.add_argument("--agent", help="list: only this agent's approvals")
    approvals.add_argument("--tool", help="list: only this tool's approvals")
    approvals.add_argument(
        "--max-age", type=int, metavar="MINUTES", help="list: only those asked for recently"
    )
    approvals.add_argument("--yes", action="store_true", help="don't ask (for scripts)")
    approvals.add_argument(
        "--across-runs",
        action="store_true",
        help="approve --yes: allow ids from separate agent runs (more than 2 min apart)",
    )
    approvals.add_argument("--warden-url", help="default WARDEN_URL or http://127.0.0.1:8000")
    init = commands.add_parser("init", help="create a starter policy file")
    init.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    commands.add_parser("schema", help="print the JSON Schema for policy files")
    test_parser = commands.add_parser("test", help="run policy tests")
    test_parser.add_argument("tests", type=Path, help="test file (JSON)")
    test_parser.add_argument("--policy", type=Path, help="policy file (overrides the test file)")
    check = commands.add_parser("check", help="validate a policy file")
    check.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    check.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    check.add_argument(
        "--agents", type=Path, help="agents file: check the agent names the policy uses"
    )
    limits = commands.add_parser("limits", help="show or change rate limits")
    limits.add_argument(
        "--policy",
        type=Path,
        default=Path(os.environ.get("WARDEN_POLICY") or DEFAULT_POLICY_PATH),
        help="policy file (env WARDEN_POLICY)",
    )
    limits_actions = limits.add_subparsers(dest="action")
    for name, help_text in [("set", "set limits"), ("reset", "remove limits")]:
        sub = limits_actions.add_parser(name, help=help_text)
        # Also accepted after the subcommand (`warden limits set --policy F`). SUPPRESS:
        # when left out here, the value given before the subcommand (or the default) stays.
        sub.add_argument("--policy", type=Path, default=argparse.SUPPRESS, help="policy file")
        sub.add_argument("--agent", help="one agent (default: every agent)")
        if name == "set":
            sub.add_argument("--requests-per-minute", type=int, help="1 to 100000")
            sub.add_argument("--pending", type=int, help="max pending approvals, 0 to 1000")
            sub.add_argument(
                "--agents",
                type=Path,
                help="agents file, to warn about unknown agents "
                f"(default WARDEN_AGENTS or {DEFAULT_AGENTS_PATH})",
            )
    proxy = commands.add_parser("proxy", help="run an MCP server behind Warden")
    proxy.add_argument("--config", type=Path, help="proxy config file (JSON)")
    proxy.add_argument(
        "--warden-url", help="default: config file, then WARDEN_URL, then http://127.0.0.1:8000"
    )
    proxy.add_argument("--agent-id", help="agent id sent to Warden (default mcp-proxy)")
    proxy.add_argument("--tool-prefix", help='put in front of tool names, e.g. "github."')
    proxy.add_argument("--approval", choices=["wait", "error"], help="default wait")
    proxy.add_argument("server", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    args = parser.parse_args(argv)

    if args.command == "proxy":
        return run_proxy(args)

    if args.command == "limits":
        from warden.limits_cli import run as run_limits

        return run_limits(args)

    if args.command == "approvals":
        from warden.approvals_cli import run as run_approvals

        return run_approvals(args)

    if args.command == "audit":
        path = args.audit_db or Path(os.environ.get("WARDEN_AUDIT_DB") or DEFAULT_AUDIT_PATH)
        if args.action == "head":
            from warden.audit_checkpoint import run_head

            return run_head(path)
        return verify_audit(path, args.expect)

    if args.command == "agent":
        return manage_agents(args.action, args.agent_id, args.agents)

    if args.command == "test":
        from warden.policy_tests import run as run_tests

        return run_tests(args.tests, args.policy)

    if args.command == "schema":
        print(policy_schema(), end="")
        return 0

    if args.command == "init":
        return init_policy(args.policy)

    if args.command == "check":
        report = check_policy(args.policy, args.agents)
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
    except OSError as exc:  # e.g. a file in a folder this user may not open
        print(f"warden: can't open {exc.filename}: {type(exc).__name__}", file=sys.stderr)
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


def verify_audit(path: Path, expect: Path | None = None) -> int:
    """`warden audit verify`: 0 intact, 1 broken, 2 can't read."""
    try:
        if not path.is_file():
            print(f"warden: no audit database at {path}", file=sys.stderr)
            return 2
        report = verify_chain(path)
    except (sqlite3.Error, OSError) as exc:
        print(f"warden: {read_error(path, exc)}", file=sys.stderr)
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
    if expect is not None:
        from warden.audit_checkpoint import run_expect

        return run_expect(path, expect)
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
    except OSError as exc:  # e.g. no such folder, or not allowed; the file is unchanged
        print(f"warden: can't use {path}: {type(exc).__name__}", file=sys.stderr)
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
        loaded = load_config(args.config) if args.config else None
        data = loaded.model_dump(exclude_unset=True) if loaded else {}
        # Where Warden is: --warden-url, then warden_url in the config file (the
        # specific, reviewed setting for this proxy), then WARDEN_URL, then the default.
        env_url = os.environ.get("WARDEN_URL")
        if env_url and (loaded is None or "warden_url" not in loaded.model_fields_set):
            data["warden_url"] = env_url
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
    except ValidationError as exc:
        print(
            f"warden proxy: invalid settings ({'; '.join(describe_errors(exc))})", file=sys.stderr
        )
        return 2
    return serve_stdio(config)


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
    print(f"  2. warden check {path}")
    print("  3. warden serve" + ("" if path == DEFAULT_POLICY_PATH else f" --policy {path}"))
    print("(in a uv project, put `uv run` in front)")
    return 0


def policy_schema() -> str:
    schema = Policy.model_json_schema(by_alias=True)
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def starter_policy() -> str:
    return resources.files("warden").joinpath("starter_policy.json").read_text(encoding="utf-8")


def run() -> None:
    sys.exit(main())
