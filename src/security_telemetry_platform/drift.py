"""Behavioral-drift detection via the Population Stability Index.

Anomaly detection catches a discrete spike; drift detection catches a slow shift
in a service's behavior distribution — request mix, latency profile, error rate —
that never trips a point threshold. The Population Stability Index (PSI) compares
a baseline distribution against a current one:

    PSI = sum_bins (current% - baseline%) * ln(current% / baseline%)

The conventional reading is PSI < 0.1 stable, 0.1-0.25 moderate drift, > 0.25
significant. Bin counts are scaled to the sample size and bin proportions use
add-one (Laplace) smoothing, so an empty bin cannot blow the log ratio up — the
classic small-sample failure mode of PSI. The computation is deterministic.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from .models import DriftAlert, Severity

DEFAULT_THRESHOLD = 0.25


def _histogram(sample: Sequence[float], edges: list[float]) -> list[int]:
    counts = [0 for _ in range(len(edges) - 1)]
    for value in sample:
        placed = False
        for index in range(len(edges) - 1):
            if value <= edges[index + 1]:
                counts[index] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    return counts


def _smoothed(counts: list[int], bins: int) -> list[float]:
    total = sum(counts)
    return [(count + 1) / (total + bins) for count in counts]


def _bin_count(baseline: Sequence[float], current: Sequence[float]) -> int:
    smallest = min(len(baseline), len(current))
    return min(10, max(3, int(smallest**0.5)))


def population_stability_index(
    baseline: Sequence[float], current: Sequence[float], *, bins: int | None = None
) -> float:
    """Return the PSI between two samples with Laplace-smoothed bins."""

    if not baseline or not current:
        return 0.0
    low = min(min(baseline), min(current))
    high = max(max(baseline), max(current))
    if high == low:
        return 0.0
    if bins is None:
        bins = _bin_count(baseline, current)
    width = (high - low) / bins
    edges = [low + width * index for index in range(bins + 1)]
    base_prop = _smoothed(_histogram(baseline, edges), bins)
    curr_prop = _smoothed(_histogram(current, edges), bins)
    return sum(
        (curr - base) * math.log(curr / base)
        for base, curr in zip(base_prop, curr_prop, strict=True)
    )


def _severity(psi: float, threshold: float) -> Severity:
    if psi >= threshold * 2:
        return Severity.HIGH
    return Severity.MEDIUM


def detect_drift(
    subject: str,
    metric: str,
    baseline: Sequence[float],
    current: Sequence[float],
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> DriftAlert | None:
    """Return a drift alert when the PSI exceeds ``threshold``, else ``None``."""

    psi = population_stability_index(baseline, current)
    if psi <= threshold:
        return None
    return DriftAlert(
        subject=subject,
        metric=metric,
        score=round(psi, 4),
        threshold=threshold,
        severity=_severity(psi, threshold),
        detail=f"PSI {psi:.3f} exceeds {threshold} for {metric} on {subject}",
    )
