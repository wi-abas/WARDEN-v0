"""The policy engine: decides allow / deny / require_approval for one request.

Security properties (each one is tested in tests/test_engine.py):
- Default deny: if no rule matches the tool, the answer is DENY.
- Tool specs: if the policy lists a tool's arguments, any other argument, or a
  missing required one, is denied before any rule runs.
- Argument conditions ("when"): a rule matches only if ALL its conditions hold.
  A condition may look inside objects (["headers", "to"]), with the same strictness.
- Never a looser answer because something is missing or odd:
  - A MISSING argument counts as "condition holds" for deny / require_approval
    rules (they apply) and as "doesn't hold" for allow rules (they don't).
    So "deny when recipient endswith evil.com" can't be dodged by leaving
    recipient out. Use the `exists` / `missing` ops to say it explicitly.
  - An argument that can't be checked denies the whole request, so a "deny"
    rule can't be dodged. "Can't be checked" means: the wrong type ("50000"
    as text for a number check), an unclean path when the rule compares paths
    ("//etc", "/./etc", "/data/../etc", "/data/.. /etc", "/data/...", backslashes),
    or not one plain email address when the rule compares emails ("x@evil.com ", "x@evil.com.",
    "Evil <x@evil.com>", "a@x.com, b@y.com"), or, when the rule compares a host
    name like "evil.com", a trailing dot, edge spaces or brackets ("x@evil.com.").
- A rule with `otherwise` gives `effect` when all its conditions hold and `otherwise`
  (always stricter) when one doesn't or its argument is missing. Uncheckable arguments
  still deny the whole request.
- Most restrictive wins: DENY beats REQUIRE_APPROVAL, which beats ALLOW.
- Fail closed: any unexpected error gives DENY, never ALLOW.
- Deterministic: no network, no files, no randomness, no LLM. Rule order does not matter.
- It only decides. It never runs the requested tool.
"""

import logging
import re
import unicodedata
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

from pydantic import JsonValue

from warden.fingerprint import fingerprint
from warden.models import (
    NUMBER_OPS,
    ActionRequest,
    Condition,
    Decision,
    EvaluationResult,
    Op,
    Rule,
    ToolSpec,
    is_number,
)

logger = logging.getLogger(__name__)

# Higher number = more restrictive. A Decision missing from this table raises
# KeyError, which the fail-closed handler in evaluate() turns into DENY.
_RESTRICTIVENESS = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.DENY: 2,
}


class _MissingArgument(Exception):
    """The argument a condition looks at is absent from the request."""


class _UncheckableArgument(Exception):
    """An argument exists but can't be compared safely (wrong type, "..", ...).

    `why` is a FIXED description of the kind of problem (never the argument's value)."""

    def __init__(self, arg: str, why: str | None = None) -> None:
        super().__init__(arg)
        self.arg = arg
        self.why = why


# Fixed reasons for text that is shaped to slip past a comparison. Never the value itself.
_HIDDEN_CHARS = "hidden or look-alike characters"
_UNCLEAN_PATH = "not a clean path: '..', '.', '//', '%', backslash or edge spaces"
_UNCLEAN_URL = "not a clean URL"
_UNCLEAN_EMAIL = "not one plain email address"
_UNCLEAN_HOST = "not a clean host name"


def _comparable(a: JsonValue, b: JsonValue) -> bool:
    """Both numbers, or exactly the same type. Avoids Python's True == 1."""
    return (is_number(a) and is_number(b)) or type(a) is type(b)


def _fold(text: str, condition: Condition) -> str:
    """Same Unicode form on both sides (NFC: a macOS "é" made of two characters equals
    the usual one), then lower-case (casefold handles e.g. German ß) if ignore_case."""
    text = unicodedata.normalize("NFC", text)
    return text.casefold() if condition.ignore_case else text


# Dots that URL and mail software treat as "." (IDNA): "evil。net" is "evil.net".
_LOOKALIKE_DOTS = {"\u3002", "\uff0e", "\uff61"}


def _check_unicode(actual: str, condition: Condition) -> None:
    """Refuse text that looks or decodes differently from what a rule sees.

    - Invisible characters (zero-width space, soft hyphen, direction marks, control
      characters): "evi\u00adl.net" is "evil.net" once software drops the soft hyphen.
    - Compatibility look-alikes that software folds into plain letters: the
      full-width "ｅ" in "ｅvil.net" becomes "e" (NFKC).
    """
    if any(unicodedata.category(ch) in {"Cf", "Cc"} for ch in actual):
        raise _UncheckableArgument(condition.label, _HIDDEN_CHARS)
    if unicodedata.normalize("NFKC", actual) != unicodedata.normalize("NFC", actual):
        raise _UncheckableArgument(condition.label, _HIDDEN_CHARS)


def _looks_like_url(value: str) -> bool:
    return "://" in value


def _looks_like_path(value: str) -> bool:
    return "/" in value and not _looks_like_url(value)


def _looks_like_email(value: str) -> bool:
    return "@" in value


_EMAIL_TRICK_CHARS = set("<>,;\"'()[]")
# Before the "@": routing tricks some mail software still honours. "%" (the "percent
# hack": user%evil.net@example.com relayed to evil.net), "!" (UUCP bang paths),
# ":" (group / source-route syntax) and "\\" (quoting).
_EMAIL_LOCAL_TRICK_CHARS = set("%!:\\")


# Percent-escapes that a decoding tool would turn into ".", "/", "\\" or "%" (double
# encoding): "/data/%2e%2e/etc" is "/data/../etc" once decoded.
_ENCODED_SEPARATORS = re.compile(r"%(2e|2f|5c|25)", re.IGNORECASE)
_ANY_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)


def _is_clean_path(text: str) -> bool:
    """No tricks that make one path look like another: //, /./, /../, backslashes, and
    no %-escapes at all (a decoding tool would read "/%65tc" as "/etc")."""
    if "\\" in text or "\x00" in text or _ANY_PERCENT_ESCAPE.search(text):
        return False
    if text != text.strip():
        return False  # " /etc/passwd" is "/etc/passwd" to a tool that trims spaces
    segments = text.split("/")
    inner = segments[1:-1] if text.startswith("/") else segments[:-1]
    if any(segment == "" for segment in inner):  # "//"
        return False
    # ".", "..", and any other segment made only of dots and spaces ("...", ".. ", " "):
    # Windows and tools that strip trailing dots/spaces read ".. " as ".." (a way out).
    return not any(segment and not segment.strip(". ") for segment in segments)


def _is_clean_url(text: str) -> bool:
    """scheme://host[:port]/clean/path, with no tricks in the host part.

    Refuses "https://good.com@evil.net" (everything before @ is a username, the real
    host is evil.net), backslashes, spaces, and unclean paths ("/a/../b", "//").
    """
    if "://" not in text or any(ch.isspace() for ch in text) or "\\" in text:
        return False
    scheme, rest = text.split("://", 1)
    if not scheme or not scheme.replace("+", "").replace("-", "").replace(".", "").isalnum():
        return False
    host, slash, path = rest.partition("/")
    if not host or "@" in host or "%" in host:
        return False
    # "evil.net.", "evil.net:" and "evil.net::443" reach the same site as "evil.net"
    # but don't match it as text. Allowed: name, name:port, [ipv6], [ipv6]:port.
    if host.startswith("["):
        name, bracket, after = host[1:].partition("]")
        if not bracket or not name or (after and not (after[0] == ":" and after[1:].isdigit())):
            return False
    else:
        name, colon, port = host.partition(":")
        if colon and not port.isdigit():
            return False
        if name.endswith("."):
            return False
    if _ENCODED_SEPARATORS.search(path):
        return False  # "/public/%2e%2e/admin" escapes "/public/" once decoded
    # Ordinary escapes like %20 are normal in URL paths; check the rest for //, /./, /../
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    return not slash or _is_clean_path("/" + _ANY_PERCENT_ESCAPE.sub("x", path_only))


def _url_host(url: str, condition: Condition) -> str:
    """The real host of a clean URL, normalized the way network software sees it:
    lowercase, no port, no trailing dot.

    International host names must be written in punycode ("xn--strae-oqa.de"). The
    Unicode form ("straße.de") is refused: Python and browsers convert it with
    different standards (IDNA2003 vs IDNA2008) and can reach DIFFERENT hosts."""
    _check_unicode(url, condition)
    if any(dot in url for dot in _LOOKALIKE_DOTS) or not _is_clean_url(url):
        raise _UncheckableArgument(condition.label, _UNCLEAN_URL)
    try:
        host = (urlsplit(url).hostname or "").rstrip(".")
    except ValueError:
        raise _UncheckableArgument(condition.label, _UNCLEAN_URL) from None
    if not host or not host.isascii():
        raise _UncheckableArgument(condition.label, _UNCLEAN_URL)
    return host.lower()


def _is_plain_email(text: str) -> bool:
    """Exactly one bare address: no spaces, no display names, no lists, no trailing dot,
    and a plain name before the "@" (not empty, no routing tricks, no stray dots)."""
    if text.count("@") != 1:
        return False
    local = text.split("@", 1)[0]
    return (
        not any(ch.isspace() for ch in text)
        and not any(ch in _EMAIL_TRICK_CHARS for ch in text)
        and not text.endswith(".")
        and local != ""
        and not any(ch in _EMAIL_LOCAL_TRICK_CHARS for ch in local)
        and not local.startswith(".")
        and not local.endswith(".")
        and ".." not in local
    )


# A host name written as plain text, e.g. "evil.com" or ".evil.com": at least two labels.
# (".txt" or "notes" are not: a file extension isn't a host.)
_DOMAIN_LIKE = re.compile(r"^\.?[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)


def _looks_like_domain(value: str) -> bool:
    return bool(_DOMAIN_LIKE.fullmatch(value))


def _is_clean_domain_text(text: str) -> bool:
    """No tricks that make text reach a host without matching it as text: a trailing
    dot ("x@evil.com." and "evil.com." reach evil.com), spaces at the edges, or the
    brackets and separators of display names and lists ("<x@evil.com>,")."""
    return (
        text == text.strip()
        and not text.endswith(".")
        and not any(ch in _EMAIL_TRICK_CHARS for ch in text)
    )


def _check_text_shape(actual: str, expected: list[str], condition: Condition) -> None:
    """Raise if the agent's text is shaped to slip past a URL, path, email or host
    name comparison."""
    if any(_looks_like_url(e) or _looks_like_email(e) or _looks_like_domain(e) for e in expected):
        if any(dot in actual for dot in _LOOKALIKE_DOTS):
            raise _UncheckableArgument(condition.label, _HIDDEN_CHARS)
    if any(_looks_like_url(e) for e in expected):
        if not _is_clean_url(actual):
            raise _UncheckableArgument(condition.label, _UNCLEAN_URL)
        return  # a URL may legitimately contain "@" in its path: skip the email check
    if any(_looks_like_domain(e) for e in expected) and not _is_clean_domain_text(actual):
        raise _UncheckableArgument(condition.label, _UNCLEAN_HOST)
    if any(_looks_like_path(e) for e in expected) and not _is_clean_path(actual):
        raise _UncheckableArgument(condition.label, _UNCLEAN_PATH)
    if any(_looks_like_email(e) for e in expected) and not _is_plain_email(actual):
        raise _UncheckableArgument(condition.label, _UNCLEAN_EMAIL)


def _same(actual: JsonValue, expected: JsonValue, condition: Condition) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return _fold(actual, condition) == _fold(expected, condition)
    return _comparable(actual, expected) and actual == expected


def _lookup(condition: Condition, arguments: dict[str, JsonValue]) -> JsonValue:
    """Follow the condition's path (["headers", "to"]) into the arguments.

    A missing key anywhere on the path: _MissingArgument (same rules as a missing
    top-level argument). Something on the path that isn't an object (a text, a number,
    a list): _UncheckableArgument, which denies the whole request, so "headers": "x"
    can't be used to dodge a rule about headers.to. Lists are never searched.
    """
    value: JsonValue = arguments
    for key in condition.path:
        if not isinstance(value, dict):
            raise _UncheckableArgument(condition.label)
        if key not in value:
            raise _MissingArgument
        value = value[key]
    return value


def _holds(condition: Condition, arguments: dict[str, JsonValue]) -> bool:
    try:
        actual = _lookup(condition, arguments)
        present = True
    except _MissingArgument:
        present = False
    if condition.op is Op.EXISTS:
        return present
    if condition.op is Op.MISSING:
        return not present
    if not present:
        raise _MissingArgument
    expected = condition.value
    op = condition.op

    if op is Op.HOST_IN:
        if not isinstance(actual, str) or not isinstance(expected, list):
            raise _UncheckableArgument(condition.label)
        host = _url_host(actual, condition)
        return any(
            host == entry or (entry.startswith(".") and (host == entry[1:] or host.endswith(entry)))
            for entry in expected
            if isinstance(entry, str)
        )

    if op in NUMBER_OPS:
        if not is_number(actual):
            raise _UncheckableArgument(condition.label)
        if not is_number(expected):  # can't happen: the policy loader checked it
            raise ValueError("policy value is not a number")
        if op is Op.GT:
            return actual > expected
        if op is Op.GTE:
            return actual >= expected
        if op is Op.LT:
            return actual < expected
        return actual <= expected  # Op.LTE

    if op in {Op.STARTSWITH, Op.ENDSWITH}:
        if not isinstance(actual, str):
            raise _UncheckableArgument(condition.label)
        if not isinstance(expected, str):  # can't happen: the policy loader checked it
            raise ValueError("policy value is not text")
        _check_unicode(actual, condition)
        _check_text_shape(actual, [expected], condition)
        text, affix = _fold(actual, condition), _fold(expected, condition)
        return text.startswith(affix) if op is Op.STARTSWITH else text.endswith(affix)

    # eq / neq / in: the argument must have the same type as the policy value(s).
    choices = expected if isinstance(expected, list) else [expected]
    if not any(_comparable(actual, choice) for choice in choices):
        raise _UncheckableArgument(condition.label)
    if isinstance(actual, str):
        _check_unicode(actual, condition)
        _check_text_shape(actual, [c for c in choices if isinstance(c, str)], condition)
    found = any(_same(actual, choice, condition) for choice in choices)
    if op is Op.NEQ:
        return not found
    return found  # Op.EQ, Op.IN


def _rule_outcome(rule: Rule, request: ActionRequest) -> Decision | None:
    """The decision this rule gives for the request, or None if it doesn't apply.

    Without `otherwise`: `effect` if every condition holds, else None.
    With `otherwise`: `effect` if every condition holds, else `otherwise` (a missing
    argument counts as "doesn't hold": the stricter branch). Either way an uncheckable
    argument raises _UncheckableArgument, which denies the whole request.
    """
    if rule.tool != request.tool:
        return None
    # A per-agent rule only applies to the agents it lists (exact match). Checked before
    # any condition: for another agent the rule simply doesn't exist.
    if not rule.applies_to(request.agent_id):
        return None
    # Check every condition (no short-circuit), so an uncheckable argument is always
    # caught, whatever order the conditions are written in.
    results = [_condition_result(rule, condition, request) for condition in rule.when]
    if all(results):
        return rule.effect
    return rule.otherwise


def _condition_result(rule: Rule, condition: Condition, request: ActionRequest) -> bool:
    try:
        return _holds(condition, request.arguments)
    except _MissingArgument:
        # Fail closed: restrictive rules still apply, allow rules don't. A rule with
        # `otherwise` takes its stricter branch ("doesn't hold").
        if rule.otherwise is not None:
            return False
        return rule.effect is not Decision.ALLOW


def evaluate(
    request: ActionRequest,
    rules: Iterable[Rule],
    tools: Mapping[str, ToolSpec] | None = None,
) -> EvaluationResult:
    """Return Warden's decision for `request` under `rules` and tool specs. Never raises."""
    try:
        return _evaluate(request, rules, tools or {})
    except Exception as exc:
        # Log only the error type: the message could contain tool arguments (secrets).
        logger.error("policy evaluation failed: %s", type(exc).__name__)
        return EvaluationResult(decision=Decision.DENY, reason="evaluation error")


def _spec_problem(request: ActionRequest, spec: ToolSpec) -> str | None:
    if any(name not in spec.arguments for name in request.arguments):
        # The name comes from the agent (untrusted, could hold a secret): don't echo it.
        return "unexpected argument"
    for name in spec.required:  # names from the policy file: safe to show
        if name not in request.arguments:
            return f"missing required argument '{name}'"
    return None


def _evaluate(
    request: ActionRequest, rules: Iterable[Rule], tools: Mapping[str, ToolSpec]
) -> EvaluationResult:
    action_hash = fingerprint(request)

    spec = tools.get(request.tool)
    if spec is not None:
        problem = _spec_problem(request, spec)
        if problem is not None:
            return EvaluationResult(decision=Decision.DENY, reason=problem, action_hash=action_hash)
    try:
        # Sorted by id so that even the reason (which argument couldn't be checked)
        # is the same whatever order the rules are written in.
        ordered = sorted(rules, key=lambda rule: rule.id)
        outcomes = [(rule, _rule_outcome(rule, request)) for rule in ordered]
        matches = [(rule, outcome) for rule, outcome in outcomes if outcome is not None]
    except _UncheckableArgument as exc:
        # exc.arg is the argument NAME from the policy file, never its value; exc.why is
        # one of the fixed texts above.
        detail = f" ({exc.why})" if exc.why else ""
        return EvaluationResult(
            decision=Decision.DENY,
            reason=f"argument '{exc.arg}' could not be checked{detail}",
            action_hash=action_hash,
        )

    if not matches:
        return EvaluationResult(
            decision=Decision.DENY, reason="no matching rule", action_hash=action_hash
        )

    # Pick the most restrictive outcome. On a tie, the smallest rule id wins,
    # so the answer is the same whatever order the rules are listed in.
    winner, decision = min(matches, key=lambda match: (-_RESTRICTIVENESS[match[1]], match[0].id))
    if decision is winner.effect:
        reason = winner.message or f"matched rule '{winner.id}'"
    else:  # the `otherwise` branch: say so, so the audit log shows which branch decided
        reason = f"rule '{winner.id}': conditions not met"

    return EvaluationResult(
        decision=decision,
        reason=reason,
        matched_rule=winner.id,
        action_hash=action_hash,
    )
