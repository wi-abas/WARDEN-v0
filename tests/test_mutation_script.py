"""The weekly mutation tester: plants bugs correctly and always restores the file."""

import ast
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parent.parent


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mutation", ROOT / "scripts" / "mutation.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE = """
def f(a, b):
    if a == b and not a:
        return True
    return a < 3
"""


def test_every_kind_of_mutation_is_planted() -> None:
    m = load()
    found = {x.description for x in m.list_mutants(SOURCE)}
    assert found == {
        "Eq -> NotEq",
        "and <-> or",
        "drop `not`",
        "True -> False",
        "Lt -> LtE",
        "3 -> 4",
    }
    mutated = [m.mutate(SOURCE, x.index) for x in m.list_mutants(SOURCE)]
    assert all(ast.parse(code) for code in mutated)
    assert len(set(mutated)) == len(mutated)  # each one is different
    assert any("a != b" in code for code in mutated)
    assert any("a == b and a" in code for code in mutated)  # "not" dropped
    with pytest.raises(IndexError):
        m.mutate(SOURCE, 99)


def test_lines_marked_as_known_survivors_are_skipped() -> None:
    m = load()
    marked = SOURCE.replace("return a < 3", "return a < 3  # mutation-ok: example")
    found = m.list_mutants(marked)
    assert {x.description for x in found} == {
        "Eq -> NotEq",
        "and <-> or",
        "drop `not`",
        "True -> False",
    }
    above = SOURCE.replace("    return a < 3", "    # mutation-ok: example\n    return a < 3")
    assert {x.description for x in m.list_mutants(above)} == {x.description for x in found}
    # Indexes still point at the same spots as without the marker.
    unmarked = {x.index: x.description for x in m.list_mutants(SOURCE)}
    assert all(unmarked[x.index] == x.description for x in found)


def test_target_file_is_always_restored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    m = load()
    (tmp_path / "toy.py").write_text(SOURCE)
    monkeypatch.setattr(m, "SRC", tmp_path)
    seen: list[str] = []
    timeouts: list[float] = []

    def runner(tests: list[str], timeout: float) -> bool:
        seen.append((tmp_path / "toy.py").read_text())
        timeouts.append(timeout)
        return len(seen) in {1, 3}  # the clean run passes; the second mutant "survives"

    tried, survivors = m.run_target("toy", ["x"], None, runner=runner)
    assert tried == 6 and [s.index for s in survivors] == [1]
    assert (tmp_path / "toy.py").read_text() == SOURCE
    assert seen[0] == SOURCE  # the clean run comes first
    assert all(code != SOURCE for code in seen[1:])
    assert timeouts[0] == 600 and all(t == 30.0 for t in timeouts[1:])  # fast toy: minimum

    def crash(tests: list[str], timeout: float) -> bool:
        if (tmp_path / "toy.py").read_text() == SOURCE:
            return True
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        m.run_target("toy", ["x"], 1, runner=crash)
    assert (tmp_path / "toy.py").read_text() == SOURCE


def test_failing_tests_stop_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """If the tests already fail, every mutant would count as caught: refuse instead."""
    m = load()
    (tmp_path / "toy.py").write_text(SOURCE)
    monkeypatch.setattr(m, "SRC", tmp_path)
    with pytest.raises(m.BaselineFailed):
        m.run_target("toy", ["x"], None, runner=lambda tests, timeout: False)
    assert (tmp_path / "toy.py").read_text() == SOURCE


def test_main_reports_and_applies_the_minimum(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    m = load()
    monkeypatch.setattr(m, "run_target", lambda name, tests, limit: (4, m.list_mutants(SOURCE)[:1]))
    assert m.main(["--target", "limits", "--min-score", "70"]) == 0
    assert "SURVIVED" in capsys.readouterr().out
    assert m.main(["--target", "limits", "--min-score", "80"]) == 1


def test_every_test_file_is_mapped_or_exempt() -> None:
    """A test file nobody lists is never run against mutants: what it checks looks
    untested, and the bugs it would catch count as survivors. So a new file must be added
    to TARGETS, or to EXEMPT with a reason."""
    m = load()
    existing = {p.name for p in (ROOT / "tests").glob("test_*.py")}
    mapped = {name for tests in m.TARGETS.values() for name in tests}
    assert existing - mapped - set(m.EXEMPT) == set(), "add to TARGETS or EXEMPT"
    assert (mapped | set(m.EXEMPT)) - existing == set(), "listed, but no such test file"
    assert mapped & set(m.EXEMPT) == set(), "both mapped and exempt"
    assert all(reason.strip() for reason in m.EXEMPT.values())
    for module, tests in m.TARGETS.items():
        assert (m.SRC / f"{module}.py").is_file(), module
        assert len(set(tests)) == len(tests), f"{module}: a test file is listed twice"
