"""Explicit detector execution accounting for ERSEC.

The runner is intentionally side-effect free apart from invoking the supplied
callable.  It prevents detector exceptions from disappearing into a successful
scan and gives CI/reporting a deterministic aggregate status.
"""
from __future__ import annotations
import time

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ersec.ersec_interfaces import DetectorResult, ExecutionStatus, ExecutionMetadata


@dataclass
class DetectorExecutionSummary:
    total: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    failures: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    skipped: int = 0
    incomplete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "by_status": dict(sorted(self.by_status.items())),
            "failures": list(self.failures),
            "finding_count": len(self.findings),
            "skipped": self.skipped,
            "incomplete": self.incomplete,
        }


class DetectorExecutionRunner:
    """Run structured detector callables and account for every execution."""

    def run(self, tasks: Iterable[Callable[[], DetectorResult]]) -> DetectorExecutionSummary:
        summary = DetectorExecutionSummary()
        for index, task in enumerate(tasks):
            summary.total += 1
            try:
                result = task()
                if not isinstance(result, DetectorResult):
                    raise TypeError("detector task returned a non-DetectorResult value")

                # Capture detector metadata if the task is a Detector instance
                if hasattr(task, "metadata"):
                    result.metadata = result.metadata or ExecutionMetadata(
                        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        detector_id=task.metadata.detector_id
                    )
            except Exception as exc:  # detector failures are explicit, not silent
                result = DetectorResult(status=ExecutionStatus.ERROR, error=str(exc)[:500])

            status = result.status.value if isinstance(result.status, ExecutionStatus) else str(result.status)
            summary.by_status[status] = summary.by_status.get(status, 0) + 1
            summary.findings.extend(result.findings)
            if result.status is ExecutionStatus.SKIPPED:
                summary.skipped += 1
            if result.status in {ExecutionStatus.ERROR, ExecutionStatus.INCONCLUSIVE,
                                 ExecutionStatus.NOT_TESTED, ExecutionStatus.SKIPPED}:
                summary.incomplete = True
            if result.status is ExecutionStatus.ERROR:
                summary.failures.append({
                    "index": index,
                    "detector_id": getattr(result.metadata, "detector_id", "") if result.metadata else "",
                    "error": result.error or "detector execution failed",
                })
        return summary
