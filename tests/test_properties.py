"""Property-based tests: rules that must ALWAYS hold, checked against thousands of
generated inputs (Hypothesis). When one breaks, Hypothesis shrinks the input to the
smallest example that still breaks it.

Run more examples locally with:  HYPOTHESIS_PROFILE=deep uv run pytest tests/test_properties.py
"""

import json
import os
import posixpath
import unicodedata
from typing import Any
from urllib.parse import unquote, urlsplit

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from warden.approvals import ApprovalStore
from warden.engine import evaluate
from warden.fingerprint import fingerprint
from warden.models import ActionRequest, Decision, EvaluationResult, Rule
from warden.policy import Policy

settings.register_profile(
    "default", max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.register_profile("deep", max_examples=5000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

TOOLS = ["t1", "t2"]
ARGS = ["a", "b", "path", "to", "url"]
WEIRD_TEXT = st.sampled_from(
    [
        "x",
        "X",
        "/data/",
        "/etc/",
        "@evil.com",
        "https://evil.net/",
        "",
        " ",
        "a..b",
        "ß",
        "ｅvil",
        "evil。net",
        "%2e%2e",
        "​",
        "1",
    ]
)
TEXT = st.one_of(WEIRD_TEXT, st.text(max_size=12))
SCALAR = st.one_of(
    TEXT, st.integers(-10, 10), st.floats(-10, 10, allow_nan=False), st.booleans(), st.none()
)
JSON_VALUE = st.recursive(
    SCALAR,
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(TEXT, inner, max_size=3),
    max_leaves=6,
)
EFFECT = st.sampled_from(["allow", "deny", "require_approval"])


@st.composite
def conditions(draw: st.DrawFn) -> dict[str, Any]:
    op = draw(
        st.sampled_from(
            [
                "eq",
                "neq",
                "gt",
                "gte",
                "lt",
                "lte",
                "in",
                "startswith",
                "endswith",
                "exists",
                "missing",
                "host_in",
            ]
        )
    )
    cond: dict[str, Any] = {"arg": draw(st.sampled_from(ARGS)), "op": op}
    if op in {"gt", "gte", "lt", "lte"}:
        cond["value"] = draw(st.integers(-5, 5) | st.floats(-5, 5, allow_nan=False))
    elif op == "in":
        cond["value"] = draw(
            st.lists(st.sampled_from(["x", "y", "/etc/", "a@b.com", "3"]), min_size=1, max_size=3)
        )
    elif op in {"startswith", "endswith"}:
        cond["value"] = draw(
            st.sampled_from(["/data/", "/etc/", "@evil.com", "https://evil.net/", "x"])
        )
    elif op in {"eq", "neq"}:
        cond["value"] = draw(st.sampled_from(["x", "/etc/passwd", "a@b.com", 3, True]))
    elif op == "host_in":
        cond["value"] = draw(
            st.lists(
                st.sampled_from(["evil.net", ".evil.org", "api.good.com"]), min_size=1, max_size=2
            )
        )
    texts = cond.get("value")
    texts = texts if isinstance(texts, list) else [texts]
    if op in {"eq", "neq", "in", "startswith", "endswith"} and all(
        isinstance(t, str) for t in texts
    ):
        cond["ignore_case"] = draw(st.booleans())
    return cond


@st.composite
def policies(draw: st.DrawFn) -> Policy:
    n = draw(st.integers(0, 6))
    rules = []
    for i in range(n):
        rule: dict[str, Any] = {
            "id": f"r{i}",
            "tool": draw(st.sampled_from(TOOLS)),
            "effect": draw(EFFECT),
        }
        if draw(st.booleans()):
            rule["when"] = draw(st.lists(conditions(), min_size=1, max_size=3))
        rules.append(rule)
    return Policy.model_validate_json(json.dumps({"rules": rules}))


@st.composite
def requests(draw: st.DrawFn) -> ActionRequest:
    names = draw(st.lists(st.sampled_from(ARGS), unique=True, max_size=4))
    arguments = {name: draw(JSON_VALUE) for name in names}
    return ActionRequest.model_validate(
        {"agent_id": "a", "tool": draw(st.sampled_from(TOOLS)), "arguments": arguments}
    )


def answer(result: EvaluationResult) -> tuple[str, str, str | None]:
    return result.decision.value, result.reason, result.matched_rule


def unconditional(tool: str, effect: str, rule_id: str) -> Rule:
    return Rule.model_validate_json(json.dumps({"id": rule_id, "tool": tool, "effect": effect}))


# --- The engine ------------------------------------------------------------------------


@given(policies(), requests())
def test_never_crashes_into_an_evaluation_error(policy: Policy, request: ActionRequest) -> None:
    assert evaluate(request, policy.rules).reason != "evaluation error"


@given(policies(), requests(), st.randoms())
def test_rule_order_never_matters(policy: Policy, request: ActionRequest, rnd: Any) -> None:
    shuffled = list(policy.rules)
    rnd.shuffle(shuffled)
    assert answer(evaluate(request, shuffled)) == answer(evaluate(request, policy.rules))


@given(policies(), requests())
def test_no_rule_for_the_tool_means_deny(policy: Policy, request: ActionRequest) -> None:
    rules = [r for r in policy.rules if r.tool != request.tool]
    assert evaluate(request, rules).decision is Decision.DENY


@given(policies(), requests())
def test_unconditional_deny_always_wins(policy: Policy, request: ActionRequest) -> None:
    rules = [*policy.rules, unconditional(request.tool, "deny", "zz-deny")]
    assert evaluate(request, rules).decision is Decision.DENY


@given(policies(), requests())
def test_allow_only_comes_from_an_allow_rule(policy: Policy, request: ActionRequest) -> None:
    result = evaluate(request, policy.rules)
    if result.decision is Decision.ALLOW:
        winner = next(r for r in policy.rules if r.id == result.matched_rule)
        assert winner.effect is Decision.ALLOW
    without_allows = [r for r in policy.rules if r.effect is not Decision.ALLOW]
    assert evaluate(request, without_allows).decision is not Decision.ALLOW


# --- Fingerprints ----------------------------------------------------------------------


@given(requests(), st.randoms())
def test_fingerprint_ignores_key_order(request: ActionRequest, rnd: Any) -> None:
    items = list(request.arguments.items())
    rnd.shuffle(items)
    reordered = request.model_copy(update={"arguments": dict(items)})
    assert fingerprint(reordered) == fingerprint(request)


@given(requests(), JSON_VALUE)
def test_any_changed_argument_changes_the_fingerprint(request: ActionRequest, new: Any) -> None:
    for name, old in request.arguments.items():
        if json.dumps(new, sort_keys=True) != json.dumps(old, sort_keys=True):
            changed = request.model_copy(update={"arguments": {**request.arguments, name: new}})
            assert fingerprint(changed) != fingerprint(request)


# --- Approvals: random sequences vs a simple model of correct behaviour ----------------

STEP = st.tuples(
    st.sampled_from(["request", "approve", "deny", "use", "use-wrong", "tick"]),
    st.integers(0, 1),
    st.sampled_from([1, 300, 899, 901]),
)


@given(st.lists(STEP, max_size=15))
def test_approvals_match_the_model(steps: list[tuple[str, int, int]]) -> None:
    now = [0.0]
    store = ApprovalStore(ttl_seconds=900, clock=lambda: now[0])
    actions = [
        ActionRequest.model_validate({"agent_id": "a", "tool": "t", "arguments": {"n": i}})
        for i in range(2)
    ]
    hashes = [fingerprint(a) for a in actions]
    model: dict[str, list[Any]] = {}  # approval_id -> [status, expires_at]
    ids: dict[int, str] = {}

    def live(approval_id: str) -> bool:
        return approval_id in model and model[approval_id][1] > now[0]

    for op, i, dt in steps:
        if op == "tick":
            now[0] += dt
        elif op == "request":
            approval_id = store.request(actions[i], hashes[i])
            assert approval_id is not None
            if not live(approval_id):
                model[approval_id] = ["pending", now[0] + 900]
            ids[i] = approval_id
        elif i in ids and op in {"approve", "deny"}:
            approval_id = ids[i]
            state = model.get(approval_id, ["gone", 0.0])
            expected = live(approval_id) and (
                state[0] == "pending" or (state[0] == "approved" and op == "deny")
            )
            try:
                store.decide(approval_id, op == "approve")
                ok = True
            except Exception:
                ok = False
            assert ok == expected
            if ok:
                state[0] = "approved" if op == "approve" else "denied"
                if op == "approve":
                    state[1] = now[0] + 900
        elif i in ids and op in {"use", "use-wrong"}:
            approval_id = ids[i]
            wrong = op == "use-wrong"
            got = store.consume(approval_id, hashes[1 - i] if wrong else hashes[i])
            expected = live(approval_id) and model[approval_id][0] == "approved" and not wrong
            assert got == expected
            if got:
                model[approval_id][0] = "used"


# --- Bypass hunting: disguised forbidden values must never be allowed ------------------


def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def _path_meaning(text: str) -> str:
    decoded = unquote(unquote(text)).replace("\\", "/").strip()
    return posixpath.normpath(_nfkc(decoded).replace("​", "").replace("­", "")).casefold()


def _url_host(text: str) -> str:
    try:
        t = _nfkc(unquote(text.strip())).replace("\\", "/").replace("。", ".")
        t = t.replace("­", "").replace("​", "")
        if t.startswith("//"):
            t = "https:" + t
        return (urlsplit(t).hostname or "").rstrip(".")
    except ValueError:
        return ""


def _mail_domain(text: str) -> str:
    t = _nfkc(text).replace("。", ".").replace("­", "").replace("​", "").strip()
    return t.rsplit("@", 1)[-1].strip("[]").rstrip(".").casefold()


PATH_TRICKS = ["//", "/./", "%2e", "%2f", "%65", "\\", " ", "ｅ", "​", "­", "E", "/x/../"]
URL_TRICKS = [":", ":443", ".", "EVIL", "ｅ", "。", "­", "%69", "@", "//", "\\", " ", "HTTP"]
MAIL_TRICKS = ["ｅ", "。", "​", "­", " ", ".", "E", "<", ",", "\n", "＠"]


def disguise(base: str, tricks: list[str]) -> st.SearchStrategy[str]:
    """Insert random tricks at random positions in `base`."""
    return st.lists(st.tuples(st.integers(0, len(base)), st.sampled_from(tricks)), max_size=4).map(
        lambda edits: _apply(base, edits)
    )


def _apply(base: str, edits: list[tuple[int, str]]) -> str:
    text = base
    for position, trick in sorted(edits, reverse=True):
        text = text[:position] + trick + text[position:]
    return text


def _allowed(rules: list[dict[str, Any]], tool: str, arg: str, value: str) -> bool:
    policy = Policy.model_validate_json(json.dumps({"rules": rules}))
    try:
        request = ActionRequest.model_validate(
            {"agent_id": "a", "tool": tool, "arguments": {arg: value}}
        )
    except ValueError:
        return False
    return evaluate(request, policy.rules).decision is Decision.ALLOW


def _deny_list(tool: str, arg: str, when: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"id": "all", "tool": tool, "effect": "allow"},
        {"id": "block", "tool": tool, "effect": "deny", "when": [when]},
    ]


@given(disguise("/etc/passwd", PATH_TRICKS))
def test_disguised_etc_paths_never_pass_a_deny_rule(path: str) -> None:
    rules = _deny_list(
        "read_file",
        "path",
        {"arg": "path", "op": "startswith", "value": "/etc/", "ignore_case": True},
    )
    if _path_meaning(path).startswith("/etc/"):
        assert not _allowed(rules, "read_file", "path", path)


@given(disguise("/data/x/../../etc/passwd", PATH_TRICKS))
def test_path_allow_list_cannot_be_escaped(path: str) -> None:
    rules = [
        {
            "id": "data",
            "tool": "read_file",
            "effect": "allow",
            "when": [{"arg": "path", "op": "startswith", "value": "/data/"}],
        }
    ]
    if not _path_meaning(path).startswith("/data/"):
        assert not _allowed(rules, "read_file", "path", path)


@given(disguise("https://evil.net/x", URL_TRICKS))
def test_disguised_hosts_never_pass_host_in(url: str) -> None:
    rules = _deny_list("fetch", "url", {"arg": "url", "op": "host_in", "value": ["evil.net"]})
    if _url_host(url) == "evil.net":
        assert not _allowed(rules, "fetch", "url", url)


@given(disguise("x@evil.com", MAIL_TRICKS))
def test_disguised_emails_never_pass_a_deny_rule(to: str) -> None:
    rules = _deny_list(
        "send_email",
        "to",
        {"arg": "to", "op": "endswith", "value": "@evil.com", "ignore_case": True},
    )
    if _mail_domain(to) == "evil.com":
        assert not _allowed(rules, "send_email", "to", to)
