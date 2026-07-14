"""Deterministic anomaly detection over metric series.

Uses the Iglewicz-Hoaglin *modified z-score*, which is built on the median and
the median absolute deviation (MAD) rather than the mean and standard deviation.
That makes it robust: a single large spike does not inflate the baseline and hide
itself, which is exactly the failure mode of a plain z-score on security metrics
like authentication failures or egress bytes. There is no learned model and no
randomness, so the same series always yields the same anomalies.
"""

from __future__ import annotations

from statistics import median

from .models import Anomaly, MetricSeries, Severity

# Constant relating the MAD to the standard deviation for a normal distribution.
_CONSISTENCY = 0.6745
DEFAULT_THRESHOLD = 3.5


def _severity(ratio: float) -> Severity:
    if ratio >= 2.5:
        return Severity.CRITICAL
    if ratio >= 1.5:
        return Severity.HIGH
    return Severity.MEDIUM


def modified_z_scores(values: tuple[float, ...]) -> list[float]:
    """Return the modified z-score of each value; empty MAD yields all zeros."""

    if not values:
        return []
    center = median(values)
    deviations = [abs(value - center) for value in values]
    mad = median(deviations)
    if mad == 0:
        return [0.0 for _ in values]
    return [_CONSISTENCY * (value - center) / mad for value in values]


def detect_anomalies(
    series: MetricSeries, *, threshold: float = DEFAULT_THRESHOLD
) -> list[Anomaly]:
    """Flag points whose absolute modified z-score exceeds ``threshold``."""

    scores = modified_z_scores(series.values)
    anomalies: list[Anomaly] = []
    for point, score in zip(series.points, scores, strict=True):
        magnitude = abs(score)
        if magnitude > threshold:
            anomalies.append(
                Anomaly(
                    metric=series.name,
                    method="modified_z_score",
                    at_epoch=point.epoch,
                    value=point.value,
                    score=round(score, 4),
                    threshold=threshold,
                    severity=_severity(magnitude / threshold),
                )
            )
    return anomalies
