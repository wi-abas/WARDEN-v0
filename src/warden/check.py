"""`warden check`: validate a policy file and warn about risky rules.

Errors: anything that would make Warden load zero rules (and deny everything).
Warnings: the policy loads, but probably doesn't do what you meant:

- W001  deny-list risk: a tool is allowed, has "deny when..." rules, but no argument
        list, so an argument no rule mentions (e.g. "bcc") is never checked.
- W002  no rules at all: every request is denied.
- W003  dead rule: an unconditional, stricter rule for the same tool always wins (a
        rule with "otherwise" also always applies, giving at least its "effect").
- W004  duplicate rule: same tool, effect and conditions as another rule.
- W005  path prefix without a trailing "/": "/data" also matches "/database"
        (and "workspace" for an argument called "path" matches "workspace-old").
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
- W016  a rule with "otherwise" uses neq or missing in "when": a double negative
        ("allow unless the value isn't X") is hard to read and easy to get backwards.
- W017  two host_in conditions on the same argument of the same tool accept different
        URL schemes: a URL outside either list is uncheckable for that rule and denies
        the whole request, even if the other rule would allow it.
- W008  an email-domain check ("...@example.com") is case-sensitive, so
        "x@EXAMPLE.com" slips past it. Add "ignore_case": true.
- W018  a deny / require_approval rule compares a host name case-sensitively, so
        "EVIL.COM" slips past it. Add "ignore_case": true.
- W019  an "allow" rule uses endswith with a bare domain: "mycompany.com" also
        matches "evilmycompany.com". Start it with "@" or ".".
- W020  two tool names differ only in upper/lower case ("getIssue" and "getissue"):
        tool names are case-sensitive, so a rule for one never applies to the other.
- W021  an "allow" rule caps a number (lt / lte) but sets no minimum: "amount lte 500"
        also allows -1000000000. Add "gte": 0 (or the real minimum), or a deny rule.

W003 and W004 take a rule's "agents" into account: a rule for every agent can make a
per-agent rule dead, but a per-agent deny never kills a rule for every agent.

Only reads the file. Never starts the server or changes anything.
"""

import json
import re
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


_CondKey = frozenset[tuple[tuple[str, ...], str, str, bool, tuple[str, ...] | None]]


def _conditions_key(rule: Rule) -> _CondKey:
    return frozenset(
        (c.path, c.op.value, json.dumps(c.value, sort_keys=True), c.ignore_case, c.schemes)
        for c in rule.when
    )


def _covers(other: Rule, rule: Rule) -> bool:
    """True if `other` applies to every agent that `rule` applies to."""
    if other.agents is None:
        return True
    return rule.agents is not None and set(rule.agents) <= set(other.agents)


_PATH_ARGUMENT = re.compile(r"(^|_)(path|dir|directory|folder)$", re.IGNORECASE)


def _is_path_prefix(arg: str, value: str) -> bool:
    """A path by its "/" or by the argument's name; not a URL, email or command."""
    if value.startswith("/"):
        return True
    if "://" in value or "@" in value or " " in value:
        return False
    return "/" in value or bool(_PATH_ARGUMENT.search(arg))


_FILE_ARGUMENT = re.compile(r"(^|_)(file|files|filename|name)$", re.IGNORECASE)
# A name with a dot that ends like a top-level domain, and not like a common file.
_HOST_NAME = re.compile(r"\.?([a-z0-9-]+\.)+(?P<end>[a-z]{2,})", re.IGNORECASE)
_FILE_ENDINGS = frozenset(
    "bak cfg conf css csv db doc docx env exe gif gz htm html ini jpeg jpg js json key lock "
    "log md pdf pem php png ppt pptx py rs sh sql svg toml ts txt xls xlsx xml yaml yml zip".split()
)


def _is_host_name(arg: str, value: object) -> bool:
    """Looks like "evil.com" or ".evil.com", and isn't a file."""
    if not isinstance(value, str) or _PATH_ARGUMENT.search(arg) or _FILE_ARGUMENT.search(arg):
        return False
    match = _HOST_NAME.fullmatch(value)
    return match is not None and match["end"].lower() not in _FILE_ENDINGS


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


def _no_minimum_warnings(rules: list[Rule]) -> list[str]:
    """W021: an allow rule with only an upper bound on a number. Negative amounts (a
    refund disguised as a payment) slip through unless something else stops them: a lower
    bound in the same rule, or a stricter rule for the tool catching small values."""
    out: list[str] = []
    for rule in rules:
        if rule.effect is not Decision.ALLOW:
            continue
        lower = {c.path for c in rule.when if c.op in {Op.GT, Op.GTE}}
        for c in rule.when:
            if c.op not in {Op.LT, Op.LTE} or c.path in lower:
                continue
            caught = any(
                other.tool == rule.tool
                and other.effect is not Decision.ALLOW
                and any(o.op in {Op.LT, Op.LTE} and o.path == c.path for o in other.when)
                for other in rules
            )
            if not caught:
                out.append(
                    f'W021: rule "{rule.id}" allows "{c.label}" {c.op.value} '
                    f"{c.value} with no minimum, so -1000000000 is allowed too. Add a "
                    f'"gte" condition (e.g. 0) or a deny rule for values below the minimum.'
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

    by_folded: dict[str, set[str]] = {}
    for tool in set(by_tool) | set(policy.tools):
        by_folded.setdefault(tool.casefold(), set()).add(tool)
    for spellings in sorted(sorted(v) for v in by_folded.values() if len(v) > 1):
        listed = '", "'.join(spellings)
        out.append(
            f'W020: tool names "{listed}" differ only in upper/lower case; tool names are '
            f"case-sensitive, so a rule for one never applies to the other (typo?)."
        )

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
                # `other` always applies (no conditions, or an `otherwise` branch) and
                # always gives at least its effect; `rule` gives at most its strictest branch.
                rule_max = rule.otherwise or rule.effect
                if (
                    (not other.when or other.otherwise is not None)
                    and other.id != rule.id
                    and _STRICTNESS[other.effect] > _STRICTNESS[rule_max]
                    and _covers(other, rule)
                ):
                    out.append(
                        f'W003: rule "{rule.id}" can never apply: "{other.id}" always '
                        f"gives {other.effect.value} for {tool}."
                    )
                    break

        seen: dict[tuple[Decision, Decision | None, _CondKey, frozenset[str] | None], str] = {}
        for rule in tool_rules:
            key = (rule.effect, rule.otherwise, _conditions_key(rule), _agents_key(rule))
            if key in seen:
                out.append(f'W004: rule "{rule.id}" duplicates rule "{seen[key]}".')
            else:
                seen[key] = rule.id

    out.extend(_no_minimum_warnings(rules))

    for rule in rules:
        spec = policy.tools.get(rule.tool)
        for c in rule.when:
            if (
                c.op is Op.STARTSWITH
                and isinstance(c.value, str)
                and _is_path_prefix(c.path[-1], c.value)
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
                c.op in {Op.EQ, Op.NEQ, Op.IN, Op.ENDSWITH, Op.CONTAINS}
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
                and c.op in {Op.EQ, Op.IN, Op.STARTSWITH, Op.ENDSWITH, Op.CONTAINS}
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
                looser_exists
                and c.op in {Op.EQ, Op.IN, Op.ENDSWITH, Op.CONTAINS}
                and not c.ignore_case
                and any(_is_host_name(c.path[-1], t) for t in texts)
            ):
                out.append(
                    f'W018: rule "{rule.id}" compares a host name case-sensitively; '
                    f'"EVIL.COM" is the same host as "evil.com". Add "ignore_case": true '
                    f"(or use host_in if the argument is a URL)."
                )
            if (
                rule.effect is Decision.ALLOW
                and c.op is Op.ENDSWITH
                and isinstance(c.value, str)
                and not c.value.startswith(".")
                and _is_host_name(c.path[-1], c.value)
            ):
                out.append(
                    f'W019: rule "{rule.id}" allows endswith "{c.value}" without a boundary, '
                    f'so it also matches "evil{c.value}". Use "@{c.value}" (email) or '
                    f'".{c.value}" (subdomains).'
                )
            if (
                rule.effect is not Decision.ALLOW
                and c.op in {Op.EQ, Op.IN, Op.STARTSWITH, Op.ENDSWITH, Op.CONTAINS}
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
            if rule.otherwise is not None and c.op in {Op.NEQ, Op.MISSING}:
                out.append(
                    f'W016: rule "{rule.id}" has "otherwise" and uses {c.op.value} on '
                    f'"{c.label}": a double negative, easy to get backwards. Prefer a '
                    f"positive condition (eq, in, exists, ...)."
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

    out += _scheme_warnings(by_tool)

    for tool in sorted(policy.tools):
        if tool not in by_tool:
            out.append(
                f'W006: tool "{tool}" has an argument list but no rules, so it\'s always denied.'
            )
    return out


def _scheme_warnings(by_tool: dict[str, list[Rule]]) -> list[str]:
    """W017: host_in conditions on one argument of one tool with different schemes."""
    out: list[str] = []
    for tool, tool_rules in sorted(by_tool.items()):
        seen: dict[tuple[str, ...], tuple[str, tuple[str, ...]]] = {}
        for rule in tool_rules:
            for c in rule.when:
                if c.op is not Op.HOST_IN:
                    continue
                schemes = tuple(sorted(c.url_schemes))
                first = seen.setdefault(c.path, (rule.id, schemes))
                if first[1] != schemes:
                    out.append(
                        f'W017: rules "{first[0]}" and "{rule.id}" check "{c.label}" of '
                        f'"{tool}" with host_in but accept different URL schemes '
                        f"({', '.join(first[1])} vs {', '.join(schemes)}); a URL outside "
                        f"either list denies the whole request. Use the same 'schemes'."
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


_CODE = re.compile(r"(W\d{3}): ")


def _split_code(warning: str) -> tuple[str | None, str]:
    """("W021", "rule ...") from "W021: rule ...", or (None, text) if it has no code."""
    match = _CODE.match(warning)
    return (match[1], warning[match.end() :]) if match else (None, warning)


def format_json(path: Path, report: Report) -> str:
    """The report as one JSON object, for scripts and CI."""
    warnings = []
    for warning in report.warnings:
        code, message = _split_code(warning)
        warnings.append({"code": code, "message": message})
    return json.dumps(
        {
            "file": str(path),
            "valid": not report.errors,
            "rules": report.rules,
            "tools": report.tools,
            "errors": report.errors,
            "warnings": warnings,
            "notes": report.notes,
        },
        indent=2,
        ensure_ascii=False,
    )


def _escape(text: str, *, prop: bool = False) -> str:
    """GitHub Actions workflow-command escaping (a newline would end the command)."""
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def format_github(path: Path, report: Report) -> str:
    """Annotations GitHub Actions shows on the pull request, then the usual report."""
    file = _escape(str(path), prop=True)
    lines = [f"::error file={file},title=warden check::{_escape(e)}" for e in report.errors]
    for warning in report.warnings:
        code, message = _split_code(warning)
        title = _escape(f"warden check {code}" if code else "warden check", prop=True)
        lines.append(f"::warning file={file},title={title}::{_escape(message)}")
    return "\n".join([*lines, format_report(path, report)])
