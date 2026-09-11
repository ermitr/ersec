"""
Rigor Tests for the Benchmark Metrics Engine.
"""
import pytest
from ersec.benchmarking.metrics import calculate_metrics

def test_perfect_detection():
    # TP=3, FP=0, FN=0
    expected = {"C1", "C2", "C3"}
    observed = {"C1", "C2", "C3"}
    scorable = {"C1", "C2", "C3"}
    metrics = calculate_metrics(expected, observed, scorable)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0

def test_total_failure():
    # TP=0, FP=3, FN=3
    expected = {"C1", "C2", "C3"}
    observed = {"C4", "C5", "C6"}
    scorable = {"C1", "C2", "C3", "C4", "C5", "C6"}
    metrics = calculate_metrics(expected, observed, scorable)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0

def test_partial_detection():
    # TP=1, FP=1, FN=1
    expected = {"C1", "C2"}
    observed = {"C1", "C3"}
    scorable = {"C1", "C2", "C3"}
    metrics = calculate_metrics(expected, observed, scorable)
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
