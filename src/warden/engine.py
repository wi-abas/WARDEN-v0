"""The policy engine: decides allow / deny / require_approval for one request.

Security properties (each one is tested in tests/test_engine.py):
- Default deny: if no rule matches the tool, the answer is DENY.
- Tool specs: if the policy lists a tool's arguments, any other argument, or a
  missing required one, is denied before any rule runs.
- Argument conditions ("when"): a rule matches only if ALL its conditions hold.
- Never a looser answer because something is missing or odd:
  - A MISSING argument counts as "condition holds" for deny / require_approval
    rules (they apply) and as "doesn't hold" for allow rules (they don't).
    So "deny when recipient endswith evil.com" can't be dodged by leaving
    recipient out. Use the `exists` / `missing` ops to say it explicitly.
  - An argument that can't be checked denies the whole request, so a "deny"
    rule can't be dodged. "Can't be checked" means: the wrong type ("50000"
    as text for a number check), an unclean path when the rule compares paths
    ("//etc", "/./etc", "/data/../etc", backslashes), or not one plain email
    address when the rule compares emails ("x@evil.com ", "x@evil.com.",
    "Evil <x@evil.com>", "a@x.com, b@y.com").
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
    """An argument exists but can't be compared safely (wrong type, "..", ...)."""

    def __init__(self, arg: str) -> None:
        super().__init__(arg)
        self.arg = arg


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
        raise _UncheckableArgument(condition.arg)
    if unicodedata.normalize("NFKC", actual) != unicodedata.normalize("NFC", actual):
        raise _UncheckableArgument(condition.arg)


def _looks_like_url(value: str) -> bool:
    return "://" in value


def _looks_like_path(value: str) -> bool:
    return "/" in value and not _looks_like_url(value)


def _looks_like_email(value: str) -> bool:
    return "@" in value


_EMAIL_TRICK_CHARS = set("<>,;\"'()[]")


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
    return not any(segment in {".", ".."} for segment in segments)


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
    if _ENCODED_SEPARATORS.search(path):
        return False  # "/public/%2e%2e/admin" escapes "/public/" once decoded
    # Ordinary escapes like %20 are normal in URL paths; check the rest for //, /./, /../
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    return not slash or _is_clean_path("/" + _ANY_PERCENT_ESCAPE.sub("x", path_only))


def _url_host(url: str, condition: Condition) -> str:
    """The real host of a clean URL, normalized the way network software sees it:
    lowercase, no port, no trailing dot, international names in punycode."""
    _check_unicode(url, condition)
    if any(dot in url for dot in _LOOKALIKE_DOTS) or not _is_clean_url(url):
        raise _UncheckableArgument(condition.arg)
    try:
        host = urlsplit(url).hostname or ""
        host = host.rstrip(".")
        if not host.isascii():
            host = host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        raise _UncheckableArgument(condition.arg) from None
    if not host:
        raise _UncheckableArgument(condition.arg)
    return host.lower()


def _is_plain_email(text: str) -> bool:
    """Exactly one bare address: no spaces, no display names, no lists, no trailing dot."""
    return (
        text.count("@") == 1
        and not any(ch.isspace() for ch in text)
        and not any(ch in _EMAIL_TRICK_CHARS for ch in text)
        and not text.endswith(".")
    )


def _check_text_shape(actual: str, expected: list[str], condition: Condition) -> None:
    """Raise if the agent's text is shaped to slip past a URL, path or email comparison."""
    if any(_looks_like_url(e) or _looks_like_email(e) for e in expected) and any(
        dot in actual for dot in _LOOKALIKE_DOTS
    ):
        raise _UncheckableArgument(condition.arg)
    if any(_looks_like_url(e) for e in expected):
        if not _is_clean_url(actual):
            raise _UncheckableArgument(condition.arg)
        return  # a URL may legitimately contain "@" in its path: skip the email check
    if any(_looks_like_path(e) for e in expected) and not _is_clean_path(actual):
        raise _UncheckableArgument(condition.arg)
    if any(_looks_like_email(e) for e in expected) and not _is_plain_email(actual):
        raise _UncheckableArgument(condition.arg)


def _same(actual: JsonValue, expected: JsonValue, condition: Condition) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return _fold(actual, condition) == _fold(expected, condition)
    return _comparable(actual, expected) and actual == expected


def _holds(condition: Condition, arguments: dict[str, JsonValue]) -> bool:
    present = condition.arg in arguments
    if condition.op is Op.EXISTS:
        return present
    if condition.op is Op.MISSING:
        return not present
    if not present:
        raise _MissingArgument
    actual = arguments[condition.arg]
    expected = condition.value
    op = condition.op

    if op is Op.HOST_IN:
        if not isinstance(actual, str) or not isinstance(expected, list):
            raise _UncheckableArgument(condition.arg)
        host = _url_host(actual, condition)
        return any(
            host == entry or (entry.startswith(".") and (host == entry[1:] or host.endswith(entry)))
            for entry in expected
            if isinstance(entry, str)
        )

    if op in NUMBER_OPS:
        if not is_number(actual):
            raise _UncheckableArgument(condition.arg)
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
            raise _UncheckableArgument(condition.arg)
        if not isinstance(expected, str):  # can't happen: the policy loader checked it
            raise ValueError("policy value is not text")
        _check_unicode(actual, condition)
        _check_text_shape(actual, [expected], condition)
        text, affix = _fold(actual, condition), _fold(expected, condition)
        return text.startswith(affix) if op is Op.STARTSWITH else text.endswith(affix)

    # eq / neq / in: the argument must have the same type as the policy value(s).
    choices = expected if isinstance(expected, list) else [expected]
    if not any(_comparable(actual, choice) for choice in choices):
        raise _UncheckableArgument(condition.arg)
    if isinstance(actual, str):
        _check_unicode(actual, condition)
        _check_text_shape(actual, [c for c in choices if isinstance(c, str)], condition)
    found = any(_same(actual, choice, condition) for choice in choices)
    if op is Op.NEQ:
        return not found
    return found  # Op.EQ, Op.IN


def _rule_matches(rule: Rule, request: ActionRequest) -> bool:
    if rule.tool != request.tool:
        return False
    # Check every condition (no short-circuit), so an uncheckable argument is always
    # caught, whatever order the conditions are written in.
    results = [_condition_result(rule, condition, request) for condition in rule.when]
    return all(results)


def _condition_result(rule: Rule, condition: Condition, request: ActionRequest) -> bool:
    try:
        return _holds(condition, request.arguments)
    except _MissingArgument:
        # Fail closed: restrictive rules still apply, allow rules don't.
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
        matches = [rule for rule in ordered if _rule_matches(rule, request)]
    except _UncheckableArgument as exc:
        # exc.arg is the argument NAME from the policy file, never its value.
        return EvaluationResult(
            decision=Decision.DENY,
            reason=f"argument '{exc.arg}' could not be checked",
            action_hash=action_hash,
        )

    if not matches:
        return EvaluationResult(
            decision=Decision.DENY, reason="no matching rule", action_hash=action_hash
        )

    # Pick the most restrictive rule. On a tie, the smallest rule id wins,
    # so the answer is the same whatever order the rules are listed in.
    winner = min(matches, key=lambda rule: (-_RESTRICTIVENESS[rule.effect], rule.id))

    return EvaluationResult(
        decision=winner.effect,
        reason=winner.message or f"matched rule '{winner.id}'",
        matched_rule=winner.id,
        action_hash=action_hash,
    )
