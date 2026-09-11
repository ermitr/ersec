import time
from ersec.ersec_scheduler import BoundedScheduler


def test_scheduler_preserves_submission_order():
    scheduler = BoundedScheduler(3)
    summary = scheduler.map([lambda: 3, lambda: 1, lambda: 2])
    assert [o.value for o in summary.outcomes] == [3, 1, 2]
    assert not summary.failures


def test_scheduler_accounts_failures():
    def boom():
        raise ValueError("boom")
    summary = BoundedScheduler(2).map([lambda: "ok", boom])
    assert summary.outcomes[0].value == "ok"
    assert isinstance(summary.outcomes[1].error, ValueError)
    assert len(summary.failures) == 1


def test_scheduler_cooperative_budget_cancellation():
    gate = {"stop": False}
    def first():
        gate["stop"] = True
        return "done"
    summary = BoundedScheduler(1).map([first, lambda: "must-not-run"], lambda: gate["stop"])
    assert summary.outcomes[0].value == "done"
    assert summary.outcomes[1].cancelled


def test_scheduler_allows_independent_work_to_overlap():
    started = time.monotonic()
    summary = BoundedScheduler(2).map([lambda: (time.sleep(0.12), 1)[1], lambda: (time.sleep(0.12), 2)[1]])
    elapsed = time.monotonic() - started
    assert [o.value for o in summary.outcomes] == [1, 2]
    assert elapsed < 0.22
