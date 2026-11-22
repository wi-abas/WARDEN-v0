"""A small mutation tester: plants one bug at a time and checks that a test catches it.

    uv run python scripts/mutation.py                 # all targets
    uv run python scripts/mutation.py --target engine --max 20

Each mutant flips one comparison (== / !=, < / <=, in / not in, is / is not), one
and / or, removes one `not`, swaps True / False, or nudges one whole number by 1, in a
security-critical module. The module's tests run against it; a mutant that no test
fails on "survives" and points at an untested behaviour. Standard library only.

The file is changed in place and ALWAYS restored (also on Ctrl-C). Run it on a clean
checkout (CI) or a clean working tree. Some survivors are equivalent mutants (the
change makes no observable difference); review them by hand.
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
        "test_tool_specs.py",
        "test_mutation_gaps.py",
    ],
    "approvals": [
        "test_approvals.py",
        "test_persistent_approvals.py",
        "test_revoke.py",
        "test_rate_limits.py",
        "test_agent_tokens.py",
        "test_mutation_gaps.py",
    ],
    "limits": ["test_rate_limits.py", "test_mutation_gaps.py"],
    "agents": ["test_agent_tokens.py"],
    "client": ["test_client.py", "test_sdk.py", "test_agent_tokens.py"],
    "sdk": ["test_sdk.py", "test_agent_tokens.py", "test_mutation_gaps.py"],
    "fingerprint": ["test_fingerprint.py"],
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


def list_mutants(source: str) -> list[Mutant]:
    tree = ast.parse(source)
    return [
        Mutant(i, getattr(node, "lineno", 0), what) for i, (node, what) in enumerate(_spots(tree))
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


def run_target(
    name: str,
    tests: list[str],
    limit: int | None,
    runner: Callable[[list[str]], bool] = run_tests,
) -> tuple[int, list[Mutant]]:
    """Plant each mutant in src/warden/<name>.py, run its tests, restore. Returns
    (mutants tried, survivors)."""
    path = SRC / f"{name}.py"
    original = path.read_text(encoding="utf-8")
    mutants = list_mutants(original)[:limit]
    survivors: list[Mutant] = []
    try:
        for mutant in mutants:
            path.write_text(mutate(original, mutant.index), encoding="utf-8")
            if runner(tests):
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
