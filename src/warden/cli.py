"""The `warden` command.

warden                 start the server (same as `warden serve`)
warden serve           start the server; options: --policy FILE --port N
                       --audit-db FILE --retention-days N (0 = keep forever).
                       Admin key: set WARDEN_ADMIN_KEY (32+ characters).
warden init [FILE]     create a starter policy (default policies/default.json)
warden check FILE      validate a policy file; exit 1 on errors
warden check --strict  ...also exit 1 on warnings (useful in CI)
warden schema          print the JSON Schema for policy files
"""

import argparse
import json
import os
import sys
from importlib import resources
from pathlib import Path

from warden import __version__
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
    init = commands.add_parser("init", help="create a starter policy file")
    init.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    commands.add_parser("schema", help="print the JSON Schema for policy files")
    check = commands.add_parser("check", help="validate a policy file")
    check.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    check.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    args = parser.parse_args(argv)

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

    from warden.api import main as serve  # imported here: `check` never loads the server

    serve(settings)
    return 0


def init_policy(path: Path) -> int:
    """Write the starter policy to `path`. Never overwrites an existing file."""
    if path.exists():
        print(f"warden: {path} already exists, not overwriting it", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(starter_policy(), encoding="utf-8")
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
