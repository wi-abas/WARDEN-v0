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
- W009  a deny / require_approval rule compares a path or URL case-sensitively, so
        "/ETC/passwd" (same file on macOS and Windows) or "HTTPS://EVIL.NET/" (hosts
        ignore case) slips past it. Add "ignore_case": true.
- W010  an "allow" rule uses neq or missing, i.e. "allow everything except X":
        a deny-list in disguise. Every value nobody thought of is allowed.
- W011  a URL prefix without "/" after the host: "https://api.example.com"
        also matches "https://api.example.com.evil.net/...".
- W012  a deny / require_approval rule compares a URL as text. "http://...",
        "https://evil.net:443/" or "https://evil.net./" slip past; use host_in.
- W013  a rule looks inside an object (["headers", "to"]) and its effect is deny /
        require_approval, but argument lists only cover top-level names, so an
        unexpected key inside the object ("headers.bcc") isn't checked.
- W014  a rule's "agents" (or limits.agents) names an agent that isn't in the agents
        file (--agents FILE): probably a typo, and `warden serve` refuses to start.
- W015  two agent names differ only in upper/lower case ("Billing" and "billing"):
        agent ids are case-sensitive, so these are two different agents.
- W008  an email-domain check ("...@example.com") is case-sensitive, so
        "x@EXAMPLE.com" slips past it. Add "ignore_case": true.

W003 and W004 take a rule's "agents" into account: a rule for every agent can make a
per-agent rule dead, but a per-agent deny never kills a rule for every agent.

Only reads the file. Never starts the server or changes anything.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from warden.agents import AgentsError, read_agents_file
from warden.models import Decision, Op, Rule
from warden.policy import DuplicateKeyError, Policy, describe_errors, named_agents, parse_policy

_STRICTNESS = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Things to know that aren't problems in the file itself (don't fail --strict).
    notes: list[str] = field(default_factory=list)
    rules: int = 0
    tools: int = 0


_CondKey = frozenset[tuple[tuple[str, ...], str, str, bool]]


def _conditions_key(rule: Rule) -> _CondKey:
    return frozenset(
        (c.path, c.op.value, json.dumps(c.value, sort_keys=True), c.ignore_case) for c in rule.when
    )


def _covers(other: Rule, rule: Rule) -> bool:
    """True if `other` applies to every agent that `rule` applies to."""
    if other.agents is None:
        return True
    return rule.agents is not None and set(rule.agents) <= set(other.agents)


def _agents_key(rule: Rule) -> frozenset[str] | None:
    return None if rule.agents is None else frozenset(rule.agents)


def _agent_warnings(policy: Policy, known_agents: list[str] | None) -> list[str]:
    out: list[str] = []
    named = named_agents(policy)
    if known_agents is not None:
        known = set(known_agents)
        for agent, where in sorted(named.items()):
            if agent not in known:
                out.append(
                    f'W014: {where[0]} names agent "{agent}", which isn\'t in the agents '
                    f"file (typo?); `warden serve` refuses to start with it."
                )
    by_folded: dict[str, set[str]] = {}
    for agent in set(named) | set(known_agents or ()):
        by_folded.setdefault(agent.casefold(), set()).add(agent)
    for spellings in sorted(sorted(v) for v in by_folded.values() if len(v) > 1):
        listed = '", "'.join(spellings)
        out.append(
            f'W015: agent names "{listed}" differ only in upper/lower case; agent ids are '
            f"case-sensitive, so these are different agents (one agent written two ways?)."
        )
    return out


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
                    and _covers(other, rule)
                ):
                    out.append(
                        f'W003: rule "{rule.id}" can never apply: "{other.id}" always '
                        f"gives {other.effect.value} for {tool}."
                    )
                    break

        seen: dict[
            tuple[
                Decision, frozenset[tuple[tuple[str, ...], str, str, bool]], frozenset[str] | None
            ],
            str,
        ] = {}
        for rule in tool_rules:
            key = (rule.effect, _conditions_key(rule), _agents_key(rule))
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
            if (
                c.op is Op.STARTSWITH
                and isinstance(c.value, str)
                and "://" in c.value
                and "/" not in c.value.split("://", 1)[1]
            ):
                out.append(
                    f'W011: rule "{rule.id}" checks startswith "{c.value}" without "/" after '
                    f'the host, so it also matches e.g. "{c.value}.evil.net/...". '
                    f'Use "{c.value}/".'
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
                and any(isinstance(t, str) and (t.startswith("/") or "://" in t) for t in texts)
            ):
                out.append(
                    f'W009: rule "{rule.id}" compares a path or URL case-sensitively; '
                    f'"/ETC/..." is the same file as "/etc/..." on macOS and Windows, and '
                    f'"HTTPS://EVIL.NET/" the same site as "https://evil.net/". '
                    f'Add "ignore_case": true.'
                )
            if (
                rule.effect is not Decision.ALLOW
                and c.op in {Op.EQ, Op.IN, Op.STARTSWITH, Op.ENDSWITH}
                and any(isinstance(t, str) and "://" in t for t in texts)
            ):
                out.append(
                    f'W012: rule "{rule.id}" blocks a URL by comparing text; "http://", a port '
                    f'or a trailing dot in the host slips past. Use "op": "host_in" with the '
                    f"host names instead."
                )
            if rule.effect is Decision.ALLOW and c.op in {Op.NEQ, Op.MISSING}:
                out.append(
                    f'W010: rule "{rule.id}" allows everything except one value ({c.op.value} '
                    f'on "{c.label}"); anything nobody thought of is allowed. Prefer listing '
                    f"what is allowed (eq, in, startswith, endswith)."
                )
            if len(c.path) > 1 and rule.effect is not Decision.ALLOW:
                out.append(
                    f'W013: rule "{rule.id}" checks "{c.label}" inside "{c.path[0]}"; other '
                    f'keys in "{c.path[0]}" (e.g. a "bcc") aren\'t checked by anything. '
                    f"Prefer an allow rule for the nested value."
                )
            if spec is not None and c.path[0] not in spec.arguments:
                out.append(
                    f'W007: rule "{rule.id}" checks argument "{c.path[0]}", which isn\'t in '
                    f'the argument list for "{rule.tool}" (typo?).'
                )

    for tool in sorted(policy.tools):
        if tool not in by_tool:
            out.append(
                f'W006: tool "{tool}" has an argument list but no rules, so it\'s always denied.'
            )
    return out


def check_policy(path: Path, agents_path: Path | None = None) -> Report:
    """Check the policy file; with `agents_path`, also the agent names it uses."""
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
        report.errors.extend(describe_errors(exc, raw))
        return report
    report.rules = len(policy.rules)
    report.tools = len({r.tool for r in policy.rules} | set(policy.tools))
    report.warnings = _warnings(policy)
    known_agents = None
    if agents_path is not None:
        try:
            known_agents = [entry.id for entry in read_agents_file(agents_path).agents]
        except AgentsError as exc:
            report.errors.append(f"agents file: {exc}")
            return report
    report.warnings += _agent_warnings(policy, known_agents)
    if known_agents is None and any(rule.agents for rule in policy.rules):
        report.notes.append(
            "the policy has per-agent rules: `warden serve` needs --agents (agent tokens) "
            "for them. Run `warden check --agents FILE` to check the agent names."
        )
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
    if report.notes:
        lines.append("")
        lines += [f"NOTE: {n}" for n in report.notes]
    lines.append("")

    def count(n: int, word: str) -> str:
        return f"{n} {word}" if n == 1 else f"{n} {word}s"

    lines.append(f"{count(len(report.errors), 'error')}, {count(len(report.warnings), 'warning')}.")
    return "\n".join(lines)
