"""`warden check`: validate a policy file and warn about risky rules.

Errors: anything that would make Warden load zero rules (and deny everything).
Warnings: the policy loads, but probably doesn't do what you meant:

- W001  deny-list risk: a tool is allowed, has "deny when..." rules, but no argument
        list, so an argument no rule mentions (e.g. "bcc") is never checked.
- W002  no rules at all: every request is denied.
- W003  dead rule: an unconditional, stricter rule for the same tool always wins.
- W004  duplicate rule: same tool, effect and conditions as another rule.
- W005  path prefix without a trailing "/": "/data" also matches "/database".
- W006  tool has an argument list but no rules: it's always denied.
- W007  a condition checks an argument that isn't in the tool's argument list
        (probably a typo): it can never be present.
- W009  a deny / require_approval rule compares a path case-sensitively, so on
        case-insensitive filesystems (macOS, Windows) "/ETC/passwd" slips past
        a rule for "/etc/". Add "ignore_case": true.
- W008  an email-domain check ("...@example.com") is case-sensitive, so
        "x@EXAMPLE.com" slips past it. Add "ignore_case": true.

Only reads the file. Never starts the server or changes anything.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from warden.models import Decision, Op, Rule
from warden.policy import DuplicateKeyError, Policy, describe_errors, parse_policy

_STRICTNESS = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rules: int = 0
    tools: int = 0


def _conditions_key(rule: Rule) -> frozenset[tuple[str, str, str, bool]]:
    return frozenset(
        (c.arg, c.op.value, json.dumps(c.value, sort_keys=True), c.ignore_case) for c in rule.when
    )


def _warnings(policy: Policy) -> list[str]:
    out: list[str] = []
    rules = sorted(policy.rules, key=lambda r: r.id)
    if not rules:
        out.append("W002: the policy has no rules, so every request is denied.")

    by_tool: dict[str, list[Rule]] = {}
    for rule in rules:
        by_tool.setdefault(rule.tool, []).append(rule)

    for tool, tool_rules in sorted(by_tool.items()):
        allowed = any(r.effect is Decision.ALLOW for r in tool_rules)
        conditional_block = any(r.when and r.effect is not Decision.ALLOW for r in tool_rules)
        if allowed and conditional_block and tool not in policy.tools:
            out.append(
                f'W001: tool "{tool}" has "deny when..." rules but no argument list. '
                f'Add a "tools" entry so unexpected arguments are denied.'
            )

        for rule in tool_rules:
            for other in tool_rules:
                if (
                    not other.when
                    and other.id != rule.id
                    and _STRICTNESS[other.effect] > _STRICTNESS[rule.effect]
                ):
                    out.append(
                        f'W003: rule "{rule.id}" can never apply: "{other.id}" always '
                        f"gives {other.effect.value} for {tool}."
                    )
                    break

        seen: dict[tuple[Decision, frozenset[tuple[str, str, str, bool]]], str] = {}
        for rule in tool_rules:
            key = (rule.effect, _conditions_key(rule))
            if key in seen:
                out.append(f'W004: rule "{rule.id}" duplicates rule "{seen[key]}".')
            else:
                seen[key] = rule.id

    for rule in rules:
        spec = policy.tools.get(rule.tool)
        for c in rule.when:
            if (
                c.op is Op.STARTSWITH
                and isinstance(c.value, str)
                and c.value.startswith("/")
                and not c.value.endswith("/")
            ):
                out.append(
                    f'W005: rule "{rule.id}" checks startswith "{c.value}" without a '
                    f'trailing "/", so it also matches e.g. "{c.value}base/...".'
                )
            texts = c.value if isinstance(c.value, list) else [c.value]
            if (
                c.op in {Op.EQ, Op.NEQ, Op.IN, Op.ENDSWITH}
                and not c.ignore_case
                and any(isinstance(t, str) and "@" in t for t in texts)
            ):
                out.append(
                    f'W008: rule "{rule.id}" compares an email address case-sensitively; '
                    f'"X@EXAMPLE.COM" would not match. Add "ignore_case": true.'
                )
            # Only risky if dodging this rule lands on a LOOSER rule for the same tool.
            looser_exists = any(
                r.tool == rule.tool and _STRICTNESS[r.effect] < _STRICTNESS[rule.effect]
                for r in rules
            )
            if (
                looser_exists
                and c.op in {Op.EQ, Op.IN, Op.STARTSWITH, Op.ENDSWITH}
                and not c.ignore_case
                and any(isinstance(t, str) and t.startswith("/") for t in texts)
            ):
                out.append(
                    f'W009: rule "{rule.id}" compares a path case-sensitively; on macOS and '
                    f'Windows "/ETC/..." is the same file as "/etc/...". Add "ignore_case": true.'
                )
            if spec is not None and c.arg not in spec.arguments:
                out.append(
                    f'W007: rule "{rule.id}" checks argument "{c.arg}", which isn\'t in '
                    f'the argument list for "{rule.tool}" (typo?).'
                )

    for tool in sorted(policy.tools):
        if tool not in by_tool:
            out.append(
                f'W006: tool "{tool}" has an argument list but no rules, so it\'s always denied.'
            )
    return out


def check_policy(path: Path) -> Report:
    report = Report()
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        report.errors.append(f"can't read {path}: {type(exc).__name__}")
        return report
    try:
        policy = parse_policy(raw)
    except DuplicateKeyError as exc:
        report.errors.append(str(exc))
        return report
    except ValidationError as exc:
        report.errors.extend(describe_errors(exc))
        return report
    report.rules = len(policy.rules)
    report.tools = len({r.tool for r in policy.rules} | set(policy.tools))
    report.warnings = _warnings(policy)
    return report


def format_report(path: Path, report: Report) -> str:
    lines = []
    if report.errors:
        lines.append(f"✗ {path}: invalid. Warden would load NO rules and deny everything.")
        lines += [f"ERROR: {e}" for e in report.errors]
    else:
        lines.append(f"✓ {path}: {report.rules} rules for {report.tools} tools")
    if report.warnings:
        lines.append("")
        lines += [f"WARNING {w}" for w in report.warnings]
    lines.append("")

    def count(n: int, word: str) -> str:
        return f"{n} {word}" if n == 1 else f"{n} {word}s"

    lines.append(f"{count(len(report.errors), 'error')}, {count(len(report.warnings), 'warning')}.")
    return "\n".join(lines)
