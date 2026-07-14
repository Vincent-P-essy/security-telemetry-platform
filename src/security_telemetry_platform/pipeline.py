"""End-to-end pipeline: ingest, detect, alert, correlate.

For each scenario the pipeline builds the telemetry, runs anomaly detection on the
metric series and drift detection on the behavior distributions, fuses everything
plus the security event into alerts, and correlates it all under the trace id.
The result is one object an analyst (or the dashboard) can read to see the whole
story of a request.
"""

from __future__ import annotations

from dataclasses import dataclass

from .alerting import build_alerts
from .anomaly import detect_anomalies
from .correlation import correlate
from .drift import detect_drift
from .loader import load_default_scenarios
from .models import Alert, AlertKind, Anomaly, CorrelatedView, DriftAlert, ScenarioSpec
from .scenarios import build_scenario, primary_service


@dataclass(frozen=True)
class ScenarioReport:
    name: str
    trace_id: str
    view: CorrelatedView
    anomalies: tuple[Anomaly, ...]
    drift_alerts: tuple[DriftAlert, ...]
    alerts: tuple[Alert, ...]

    def counts(self) -> dict[str, int]:
        return {
            "anomalies": len(self.anomalies),
            "drift_alerts": len(self.drift_alerts),
            "security_alerts": sum(1 for a in self.alerts if a.kind is AlertKind.SECURITY_EVENT),
            "total_alerts": len(self.alerts),
            "correlated_spans": len(self.view.spans),
            "correlated_logs": len(self.view.logs),
            "correlated_events": len(self.view.security_events),
        }


def run_scenario(spec: ScenarioSpec) -> ScenarioReport:
    built = build_scenario(spec)
    series = built.store.metric(spec.anomaly_metric)
    anomalies = detect_anomalies(series) if series is not None else []

    drift = detect_drift(
        subject=primary_service(spec),
        metric=spec.drift_metric,
        baseline=spec.drift_baseline,
        current=spec.drift_current,
    )
    drift_alerts = [drift] if drift is not None else []

    events = built.store.events_for(built.trace_id)
    alerts = build_alerts(
        trace_id=built.trace_id,
        anomalies=anomalies,
        drift_alerts=drift_alerts,
        security_events=events,
    )
    view = correlate(built.store, built.trace_id, tuple(alerts))
    return ScenarioReport(
        name=spec.name,
        trace_id=built.trace_id,
        view=view,
        anomalies=tuple(anomalies),
        drift_alerts=tuple(drift_alerts),
        alerts=tuple(alerts),
    )


def run_all(specs: tuple[ScenarioSpec, ...] | None = None) -> list[ScenarioReport]:
    catalogue = specs if specs is not None else load_default_scenarios()
    return [run_scenario(spec) for spec in catalogue]


def ground_truth(specs: tuple[ScenarioSpec, ...] | None = None) -> dict[str, dict[str, int]]:
    return {report.name: report.counts() for report in run_all(specs)}
