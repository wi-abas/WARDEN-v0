"""A small mutation tester: plants one bug at a time and checks that a test catches it.

    uv run python scripts/mutation.py                 # all targets
    uv run python scripts/mutation.py --target engine --max 20

Each mutant flips one comparison (== / !=, < / <=, in / not in, is / is not), one
and / or, removes one `not`, swaps True / False, or nudges one whole number by 1, in a
security-critical module. The module's tests run against it; a mutant that no test
fails on "survives" and points at an untested behaviour. Standard library only.

The file is changed in place and ALWAYS restored (also on Ctrl-C). Run it on a clean
checkout (CI) or a clean working tree. Some survivors are equivalent mutants (the
change makes no observable difference); review them by hand, and mark a reviewed line
with `# mutation-ok: <why>` so it isn't planted again.
"""

import argparse
import ast
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC = ROOT / "src" / "warden"

# Module -> the tests that should catch bugs planted in it.
TARGETS: dict[str, list[str]] = {
    "engine": [
        "test_engine.py",
        "test_conditions.py",
        "test_nested_arguments.py",
        "test_text_tricks.py",
        "test_url_rules.py",
        "test_host_in.py",
        "test_endswith.py",
        "test_unicode_tricks.py",
        "test_percent_encoding.py",
        "test_rule_matching.py",
        "test_tool_specs.py",
        "test_mutation_gaps.py",
        "test_contains.py",
        "test_otherwise.py",
        "test_per_agent_rules.py",
        "test_url_schemes.py",
        "test_rule_messages.py",
        "test_default_ignorable.py",
    ],
    "approvals": [
        "test_approvals.py",
        "test_persistent_approvals.py",
        "test_revoke.py",
        "test_rate_limits.py",
        "test_agent_tokens.py",
        "test_mutation_gaps.py",
        "test_group_approvals_store.py",
        "test_group_approvals_api.py",
        "test_group_approvals_attacks.py",
        "test_approve_what_you_saw.py",
        "test_approval_hygiene.py",
        "test_required_action_hash.py",
        "test_sticky_rejections.py",
        "test_restore_vs_rejection.py",
        "test_shared_approvals_database.py",
    ],
    "limits": [
        "test_rate_limits.py",
        "test_mutation_gaps.py",
        "test_sticky_rejections.py",
    ],
    "agents": [
        "test_agent_tokens.py",
        "test_server_identity.py",
        "test_mutation_gaps.py",
    ],
    "client": [
        "test_client.py",
        "test_client_proof.py",
        "test_sdk.py",
        "test_agent_tokens.py",
        "test_client_redirects.py",
        "test_sdk_wait_restart.py",
        "test_sdk_refusals.py",
        "test_approval_wait_deadline.py",
        "test_mutation_gaps.py",
    ],
    "sdk": [
        "test_sdk.py",
        "test_client_proof.py",
        "test_agent_tokens.py",
        "test_mutation_gaps.py",
        "test_sdk_async_waits.py",
        "test_sdk_sync_async_mix.py",
        "test_sdk_wait_restart.py",
        "test_sdk_refusals.py",
        "test_approval_wait_deadline.py",
    ],
    "fingerprint": ["test_fingerprint.py"],
    "identity": ["test_identity.py"],
    "api": [
        "test_api.py",
        "test_hardening.py",
        "test_body_limit.py",
        "test_http_errors.py",
        "test_host_check.py",
        "test_duplicate_request_keys.py",
        "test_approval_display.py",
        "test_approvals.py",
        "test_revoke.py",
        "test_group_approvals_api.py",
        "test_group_approvals_attacks.py",
        "test_approve_what_you_saw.py",
        "test_approvals_flood.py",
        "test_audit_events.py",
        "test_rejection_rate_limit.py",
        "test_locked_database.py",
        "test_agent_tokens.py",
        "test_rate_limits.py",
        "test_api_edges.py",
        "test_main_wiring.py",
        "test_health_logging.py",
        "test_approval_hygiene.py",
        "test_per_agent_rules.py",
        "test_required_action_hash.py",
        "test_sticky_rejections.py",
        "test_crash_logging.py",
        "test_default_ignorable.py",
        "test_server_identity.py",
    ],
    "audit": [
        "test_audit.py",
        "test_audit_chain.py",
        "test_audit_events.py",
        "test_audit_permissions.py",
        "test_audit_triggers.py",
        "test_audit_hot_journal.py",
        "test_retention.py",
        "test_locked_database.py",
        "test_group_approvals_api.py",
        "test_audit_edges.py",
    ],
    "audit_checkpoint": ["test_audit_checkpoint.py", "test_audit_checkpoint_edges.py"],
    "mcp_proxy": [
        "test_mcp_proxy.py",
        "test_mcp_proxy_hardening.py",
        "test_mcp_proxy_edges.py",
        "test_mcp_proxy_disconnect.py",
        "test_mcp_proxy_large_numbers.py",
        "test_approval_wait_deadline.py",
        "test_mcp_proxy_hint.py",
        "test_mcp_proxy_identity.py",
        "test_mcp_proxy_messages.py",
        "test_mcp_proxy_request_ids.py",
        "test_mcp_proxy_startup.py",
        "test_mcp_proxy_stuck_server.py",
    ],
    "approvals_cli": [
        "test_approvals_cli.py",
        "test_approvals_cli_edges.py",
        "test_approvals_cli_proof.py",
        "test_client_redirects.py",
        "test_approvals_flood.py",
        "test_approval_hygiene.py",
        "test_required_action_hash.py",
        "test_sticky_rejections.py",
        "test_mutation_gaps.py",
    ],
    "policy_tests": [
        "test_policy_tests.py",
        "test_policy_tests_edges.py",
        "test_huge_integers.py",
    ],
}

# Test files that don't run against mutants, and why. Every other one must be in TARGETS.
EXEMPT: dict[str, str] = {
    "test_adversarial_build_session.py": "cross-module fuzzing and races: too slow per mutant",
    "test_agent_example.py": "tests examples/agent.py",
    "test_benchmark_script.py": "tests scripts/benchmark.py",
    "test_check.py": "check isn't a target",
    "test_deep_nesting.py": "one parser limit across many modules, not their logic",
    "test_default_policy.py": "tests the shipped policy file",
    "test_demo.py": "tests the demo",
    "test_demo_svg.py": "tests scripts/demo_svg.py",
    "test_docs_policies.py": "tests the examples in docs/policies.md",
    "test_duplicate_keys.py": "policy isn't a target",
    "test_e2e_scenario.py": "starts real processes: too slow per mutant",
    "test_fuzz_targets.py": "fuzzing: too slow per mutant",
    "test_group_approvals_properties.py": "property test: too slow per mutant",
    "test_init.py": "cli isn't a target",
    "test_limits_cli.py": "limits_cli isn't a target",
    "test_lone_surrogates.py": "models isn't a target",
    "test_model_strictness.py": "models isn't a target; each target's own tests pin its models",
    "test_models.py": "models isn't a target",
    "test_mutation_script.py": "tests this script",
    "test_policy.py": "policy isn't a target",
    "test_policy_permissions.py": "settings isn't a target",
    "test_policy_typos.py": "models isn't a target",
    "test_properties.py": "property test: too slow per mutant",
    "test_properties_build_session.py": "property test: too slow per mutant",
    "test_proxy_warden_url.py": "tests the proxy's command line (cli isn't a target)",
    "test_schema.py": "the JSON Schema file",
    "test_serve_refuses_bad_policy.py": "cli isn't a target",
    "test_settings.py": "settings isn't a target",
    "test_startup_errors.py": "cli isn't a target",
}

_SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
}


@dataclass(frozen=True)
class Mutant:
    index: int  # the n-th mutable spot in the file
    line: int
    description: str


def _spots(tree: ast.AST) -> Iterator[tuple[ast.AST, str]]:
    """Every place a mutation can be planted, in a stable order."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if type(op) in _SWAPS:
                    yield node, f"{type(op).__name__} -> {_SWAPS[type(op)].__name__}"
        elif isinstance(node, ast.BoolOp):
            yield node, "and <-> or"
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield node, "drop `not`"
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            yield node, f"{node.value} -> {not node.value}"
        elif (
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and getattr(node, "lineno", 0) > 0
        ):
            yield node, f"{node.value} -> {node.value + 1}"


# A source line with this comment is skipped: every mutant on it was reviewed and can't
# (or needn't) be caught, e.g. a SQLite timeout or a case handled earlier. The comment
# must say why, so the reason is visible next to the code in every review. On a line of
# its own, it covers the line below (for lines too long for a comment at the end).
KNOWN_SURVIVOR = "# mutation-ok:"


def _known_lines(source: str) -> set[int]:
    known = set()
    for number, text in enumerate(source.splitlines(), start=1):
        if KNOWN_SURVIVOR in text:
            known.add(number + 1 if text.strip().startswith(KNOWN_SURVIVOR) else number)
    return known


def list_mutants(source: str) -> list[Mutant]:
    tree = ast.parse(source)
    known = _known_lines(source)
    return [
        Mutant(i, line, what)
        for i, (node, what) in enumerate(_spots(tree))
        if (line := getattr(node, "lineno", 0)) not in known
    ]


def _change(node: ast.AST) -> None:
    """Plant one mutation in `node` (anything but `not`, see _DropNot)."""
    if isinstance(node, ast.Compare):
        for k, op in enumerate(node.ops):
            if type(op) in _SWAPS:
                node.ops[k] = _SWAPS[type(op)]()
                return  # one comparison operator per mutant
    elif isinstance(node, ast.BoolOp):
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
        node.value = not node.value
    elif isinstance(node, ast.Constant) and type(node.value) is int:
        node.value = node.value + 1


class _DropNot(ast.NodeTransformer):
    """`not x` -> `x` (UnaryOp can't change its own type in place)."""

    def __init__(self, target_node: ast.AST) -> None:
        self.target_node = target_node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:  # noqa: N802 (ast naming)
        if node is self.target_node:
            return node.operand
        return self.generic_visit(node)


def mutate(source: str, index: int) -> str:
    """The source with mutant number `index` planted."""
    tree = ast.parse(source)
    for i, (node, _) in enumerate(_spots(tree)):
        if i == index:
            if isinstance(node, ast.UnaryOp):
                tree = _DropNot(node).visit(tree)
            else:
                _change(node)
            break
    else:
        raise IndexError(index)
    return ast.unparse(ast.fix_missing_locations(tree))


def run_tests(tests: list[str], timeout: float = 300) -> bool:
    """True if the tests pass (i.e. the mutant SURVIVED)."""
    command = [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"]
    command += [str(ROOT / "tests" / t) for t in tests]
    try:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)  # noqa: S603
    except subprocess.TimeoutExpired:
        return False  # a hang counts as caught
    return done.returncode == 0


class BaselineFailed(Exception):
    """The tests fail before any mutation: every mutant would look 'caught'."""


def run_target(
    name: str,
    tests: list[str],
    limit: int | None,
    runner: Callable[..., bool] = run_tests,
) -> tuple[int, list[Mutant]]:
    """Plant each mutant in src/warden/<name>.py, run its tests, restore. Returns
    (mutants tried, survivors).

    The tests first run once unchanged: they must pass, and their time sets the
    timeout for each mutant (10x, at least 30 s), so a mutant that makes a test hang
    costs seconds instead of minutes.
    """
    path = SRC / f"{name}.py"
    original = path.read_text(encoding="utf-8")
    mutants = list_mutants(original)[:limit]
    started = time.monotonic()
    if not runner(tests, timeout=600):
        raise BaselineFailed(f"{name}: its tests fail without any mutation")
    budget = max(30.0, 10 * (time.monotonic() - started))
    survivors: list[Mutant] = []
    try:
        for mutant in mutants:
            path.write_text(mutate(original, mutant.index), encoding="utf-8")
            if runner(tests, timeout=budget):
                survivors.append(mutant)
    finally:
        path.write_text(original, encoding="utf-8")
    return len(mutants), survivors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", choices=sorted(TARGETS), action="append")
    parser.add_argument("--max", type=int, help="at most this many mutants per module")
    parser.add_argument("--min-score", type=float, default=0.0, help="fail below this %%")
    args = parser.parse_args(argv)

    total = caught = 0
    started = time.monotonic()
    for name in args.target or sorted(TARGETS):
        tried, survivors = run_target(name, TARGETS[name], args.max)
        total += tried
        caught += tried - len(survivors)
        print(f"{name}: {tried - len(survivors)}/{tried} caught")
        for mutant in survivors:
            print(f"  SURVIVED src/warden/{name}.py:{mutant.line}  {mutant.description}")
    score = 100.0 * caught / total if total else 100.0
    print(f"\nScore: {caught}/{total} = {score:.1f}% ({time.monotonic() - started:.0f} s)")
    return 0 if score >= args.min_score else 1


if __name__ == "__main__":
    sys.exit(main())
