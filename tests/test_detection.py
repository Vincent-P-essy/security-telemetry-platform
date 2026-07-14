from __future__ import annotations

from security_telemetry_platform.anomaly import detect_anomalies, modified_z_scores
from security_telemetry_platform.drift import detect_drift, population_stability_index
from security_telemetry_platform.models import MetricPoint, MetricSeries, Severity


def _series(values: list[float]) -> MetricSeries:
    return MetricSeries(
        name="metric",
        points=tuple(MetricPoint(epoch=float(i), value=v) for i, v in enumerate(values)),
    )


def test_spike_is_flagged() -> None:
    anomalies = detect_anomalies(_series([3, 4, 3, 5, 4, 3, 4, 5, 3, 4, 95, 3]))
    assert len(anomalies) == 1
    assert anomalies[0].value == 95
    assert anomalies[0].severity is Severity.CRITICAL


def test_flat_series_has_no_anomaly() -> None:
    # A perfectly flat series has zero MAD; the detector must not divide by zero.
    assert detect_anomalies(_series([5, 5, 5, 5, 5])) == []
    assert modified_z_scores(()) == []
    assert modified_z_scores((5.0, 5.0, 5.0)) == [0.0, 0.0, 0.0]


def test_gentle_variation_is_not_anomalous() -> None:
    assert detect_anomalies(_series([100, 105, 98, 102, 101, 99, 103, 100])) == []


def test_psi_separates_stable_from_shifted() -> None:
    stable = population_stability_index(
        [100, 105, 98, 102, 101, 99, 103, 100], [101, 99, 104, 100, 98, 102, 101, 103]
    )
    shifted = population_stability_index([110, 120, 115, 125, 118], [280, 300, 290, 310, 305])
    assert stable < 0.25
    assert shifted > 0.25


def test_detect_drift_alert_and_none() -> None:
    alert = detect_drift(
        "checkout", "latency", [110, 120, 115, 125, 118], [280, 300, 290, 310, 305]
    )
    assert alert is not None
    assert alert.score > 0.25
    assert detect_drift("checkout", "latency", [1, 2, 3, 4], [1, 2, 3, 4]) is None


def test_psi_edge_cases() -> None:
    assert population_stability_index([], [1, 2]) == 0.0
    assert population_stability_index([5, 5, 5], [5, 5, 5]) == 0.0
