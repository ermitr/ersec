"""Benchmark execution boundary used during modular migration."""
from __future__ import annotations
from typing import Any, Mapping

class BenchmarkExecutionError(RuntimeError):
    pass

class SafeBenchmarkRunner:
    def __init__(self, oracle: Any):
        self.oracle = oracle
    def evaluate(self, report: Mapping[str, Any], truth: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.oracle is None or not hasattr(self.oracle, "evaluate"):
            raise BenchmarkExecutionError("benchmark oracle is unavailable")
        result = self.oracle.evaluate(report, truth)
        if not isinstance(result, Mapping):
            raise BenchmarkExecutionError("benchmark oracle returned a non-mapping result")
        return result
