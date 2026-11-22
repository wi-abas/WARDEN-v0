"""The `warden` command.

warden                 start the server (same as `warden serve`)
warden serve           start the server
warden check FILE      validate a policy file; exit 1 on errors
warden check --strict  ...also exit 1 on warnings (useful in CI)
"""

import argparse
import sys
from pathlib import Path

from warden.check import check_policy, format_report
from warden.policy import DEFAULT_POLICY_PATH


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="start the server")
    check = commands.add_parser("check", help="validate a policy file")
    check.add_argument("policy", nargs="?", type=Path, default=DEFAULT_POLICY_PATH)
    check.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    args = parser.parse_args(argv)

    if args.command == "check":
        report = check_policy(args.policy)
        print(format_report(args.policy, report))
        return 1 if report.errors or (args.strict and report.warnings) else 0

    from warden.api import main as serve  # imported here: `check` never loads the server

    serve()
    return 0


def run() -> None:
    sys.exit(main())
