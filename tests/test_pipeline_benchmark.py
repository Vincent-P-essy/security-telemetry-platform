from __future__ import annotations

import json
from pathlib import Path

from security_telemetry_platform.alerting import build_alerts
from security_telemetry_platform.benchmark import (
    _percentile,
    benchmark,
    committed_ground_truth,
    write_benchmark,
)
from security_telemetry_platform.loader import load_default_scenarios
from security_telemetry_platform.models import (
    AlertKind,
    Anomaly,
    DriftAlert,
    SecurityEvent,
    Severity,
)
from security_telemetry_platform.pipeline import ground_truth, run_all, run_scenario
from security_telemetry_platform.reporting import render_markdown, summarize, write_report
from security_telemetry_platform.resources import packaged_path


def test_all_scenarios_match_ground_truth() -> None:
    committed = json.loads(packaged_path("ground-truth.json").read_text(encoding="utf-8"))
    assert committed == ground_truth() == committed_ground_truth()
    for report in run_all():
        assert report.counts() == committed[report.name]


def test_drift_catches_what_anomaly_misses() -> None:
    spec = next(s for s in load_default_scenarios() if s.name == "latency-drift")
    report = run_scenario(spec)
    assert report.counts()["anomalies"] == 0
    assert report.counts()["drift_alerts"] == 1


def test_incident_correlates_every_signal() -> None:
    spec = next(s for s in load_default_scenarios() if s.name == "credential-stuffing")
    report = run_scenario(spec)
    assert report.view.security_events
    assert report.view.metrics
    assert {a.kind for a in report.alerts} == {
        AlertKind.ANOMALY,
        AlertKind.DRIFT,
        AlertKind.SECURITY_EVENT,
    }
    assert all(a.trace_id == report.trace_id for a in report.alerts)


def test_alerting_dedup_and_rank() -> None:
    anomaly = Anomaly(
        metric="m",
        method="modified_z_score",
        at_epoch=1,
        value=9,
        score=9,
        threshold=3.5,
        severity=Severity.HIGH,
    )
    drift = DriftAlert(
        subject="svc", metric="m", score=0.5, threshold=0.25, severity=Severity.MEDIUM, detail="x"
    )
    event = SecurityEvent(
        id="e", epoch=1, category="exfil", severity=Severity.CRITICAL, service="svc", detail="d"
    )
    alerts = build_alerts(
        trace_id=None, anomalies=[anomaly], drift_alerts=[drift], security_events=[event]
    )
    assert len(alerts) == 3
    # Sorted by severity descending: critical event first.
    assert alerts[0].severity is Severity.CRITICAL
    # Idempotent: same inputs collapse to the same ids.
    again = build_alerts(
        trace_id=None, anomalies=[anomaly, anomaly], drift_alerts=[drift], security_events=[event]
    )
    assert len(again) == 3


def test_percentile() -> None:
    assert _percentile([], 50) == 0.0
    assert _percentile([1.0, 2.0, 3.0], 50) == 2.0


def test_benchmark_is_deterministic() -> None:
    result = benchmark(iterations=5)
    assert result.deterministic is True
    assert result.ground_truth_verified is True
    assert result.exports_valid is True
    assert result.matched == result.scenarios == 4
    assert result.incidents == 2
    assert result.report_hash


def test_write_benchmark(tmp_path: Path) -> None:
    path = write_benchmark(tmp_path, benchmark(iterations=2))
    assert json.loads(path.read_text(encoding="utf-8"))["iterations"] == 2


def test_reporting(tmp_path: Path) -> None:
    reports = run_all()
    summary = summarize(reports)
    assert summary["scenarios"] == 4
    assert summary["incidents"] == 2
    assert "correlation" in render_markdown(reports)
    paths = write_report(tmp_path, reports)
    assert paths["json"].exists()
    assert paths["markdown"].exists()
