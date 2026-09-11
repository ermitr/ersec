"""Bounded concurrent scheduling primitives for ERSEC 29.1.1.

The scheduler keeps orchestration policy out of the monolithic runtime. It is
purposefully small: bounded workers, deterministic submission order, explicit
failure accounting, and cooperative cancellation when a shared safety budget
is exhausted. It never changes scope or authorization policy.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable, Any


@dataclass
class TaskOutcome:
    index: int
    value: Any = None
    error: Exception | None = None
    cancelled: bool = False


@dataclass
class BatchSummary:
    outcomes: list[TaskOutcome] = field(default_factory=list)

    @property
    def failures(self) -> list[TaskOutcome]:
        return [x for x in self.outcomes if x.error is not None]

    @property
    def cancelled(self) -> list[TaskOutcome]:
        return [x for x in self.outcomes if x.cancelled]


class BoundedScheduler:
    """Execute independent work with a hard worker ceiling.

    Tasks are submitted in caller order, while results are collected as they
    finish. A cancellation predicate can stop queued work when a shared budget
    (for example ERSEC's request budget) becomes exhausted.
    """

    def __init__(self, max_workers: int):
        self.max_workers = max(1, int(max_workers))

    def map(self, tasks: Iterable[Callable[[], Any]],
            should_cancel: Callable[[], bool] | None = None) -> BatchSummary:
        task_list = list(tasks)
        if not task_list:
            return BatchSummary()
        if self.max_workers == 1:
            outcomes: list[TaskOutcome] = []
            for index, task in enumerate(task_list):
                if should_cancel and should_cancel():
                    outcomes.append(TaskOutcome(index=index, cancelled=True))
                    continue
                try:
                    outcomes.append(TaskOutcome(index=index, value=task()))
                except Exception as exc:  # accounted by caller; never silent
                    outcomes.append(TaskOutcome(index=index, error=exc))
            return BatchSummary(outcomes)

        outcomes: list[TaskOutcome] = []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(task_list)),
                                thread_name_prefix="ersec-worker") as executor:
            futures = {}
            for index, task in enumerate(task_list):
                if should_cancel and should_cancel():
                    outcomes.append(TaskOutcome(index=index, cancelled=True))
                    continue
                futures[executor.submit(task)] = index
            for future in as_completed(futures):
                index = futures[future]
                try:
                    outcomes.append(TaskOutcome(index=index, value=future.result()))
                except Exception as exc:
                    outcomes.append(TaskOutcome(index=index, error=exc))
                if should_cancel and should_cancel():
                    for pending in futures:
                        if not pending.done():
                            pending.cancel()
        return BatchSummary(sorted(outcomes, key=lambda x: x.index))
