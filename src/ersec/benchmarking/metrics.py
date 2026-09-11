"""
ERSEC Benchmark Metrics Engine.
Provides standardized calculation of security detection quality (Precision, Recall, F1).
"""
from __future__ import annotations
from typing import Any, Dict, List, Mapping, Sequence, Set
import statistics

def calculate_metrics(
    expected_positives: Set[str],
    observed_positives: Set[str],
    scorable_ids: Set[str]
) -> Dict[str, Any]:
    """
    Calculate standard detection metrics.

    Args:
        expected_positives: Set of case IDs that SHOULD have been flagged (True Positives + False Negatives).
        observed_positives: Set of case IDs that WERE flagged (True Positives + False Positives).
        scorable_ids: Set of all case IDs that are not 'ambiguous'.

    Returns:
        A dictionary containing TP, FP, FN, Precision, Recall, and F1.
    """
    tp = len(expected_positives & observed_positives)
    fp = len(observed_positives - expected_positives)
    fn = len(expected_positives - observed_positives)

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }

def calculate_runtime_stats(samples: Sequence[float]) -> Dict[str, Any]:
    """Calculate deterministic runtime statistics."""
    if not samples:
        return {"mean": 0.0, "max": 0.0, "variance": 0.0}

    return {
        "mean": round(statistics.mean(samples), 6),
        "max": round(max(samples), 6),
        "variance": round(statistics.pvariance(samples), 9) if len(samples) > 1 else 0.0,
    }
