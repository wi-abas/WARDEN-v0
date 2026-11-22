"""The `warden` command.

warden                 start the server (same as `warden serve`)
warden serve           start the server
warden check FILE      validate a policy file; exit 1 on errors
warden check --strict  ...also exit 1 on warnings (useful in CI)
"""

import argparse
import os
import sys
from pathlib import Path

from warden.check import check_policy, format_report
from warden.policy import DEFAULT_POLICY_PATH
from warden.settings import SettingsError, resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command")
    serve_parser = commands.add_parser("serve", help="start the server")
    serve_parser.add_argument("--policy", help="policy file (env WARDEN_POLICY)")
    serve_parser.add_argument("--port", help="port, default 8000 (env WARDEN_PORT)")
    serve_parser.add_argument("--audit-db", help="audit database file (env WARDEN_AUDIT_DB)")
    serve_parser.add_argument(
        "--retention-days",
        help="days to keep audit entries, 0 = forever (env WARDEN_RETENTION_DAYS)",
    )
    check = commands.add_parser("check", help="validate a policy file")
    check.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    check.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    args = parser.parse_args(argv)

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

    from warden.api import main as serve  # imported here: `check` never loads the server

    serve(settings)
    return 0


def run() -> None:
    sys.exit(main())
