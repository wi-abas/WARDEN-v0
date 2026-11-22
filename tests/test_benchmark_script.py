"""Smoke test: the benchmark script keeps working (tiny run, no timing asserts)."""

import importlib.util
from pathlib import Path


def test_benchmark_runs() -> None:
    path = Path(__file__).parent.parent / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark", path)
    assert spec is not None and spec.loader is not None
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    assert "median" in bench.bench_engine(n=200)
    assert "median" in bench.bench_http(n=30)
