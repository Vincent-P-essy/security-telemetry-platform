"""Fuse anomalies, drift, and security events into deduplicated alerts.

Alerts from all three sources are normalized into one :class:`Alert` type, given
a stable id (so the same finding does not fire twice), and ranked by severity.
Keeping the trace id on every alert is what lets the correlation view tie an alert
back to the request that produced it.
"""

from __future__ import annotations

import hashlib

from .models import Alert, AlertKind, Anomaly, DriftAlert, SecurityEvent, Severity

_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _alert_id(kind: AlertKind, source: str, key: str) -> str:
    digest = hashlib.sha256(f"{kind.value}|{source}|{key}".encode()).hexdigest()
    return f"alert-{digest[:12]}"


def build_alerts(
    *,
    trace_id: str | None,
    anomalies: list[Anomaly],
    drift_alerts: list[DriftAlert],
    security_events: list[SecurityEvent],
) -> list[Alert]:
    """Return deduplicated, severity-ranked alerts from all three sources."""

    by_id: dict[str, Alert] = {}

    for anomaly in anomalies:
        alert = Alert(
            id=_alert_id(AlertKind.ANOMALY, anomaly.metric, f"{anomaly.at_epoch}"),
            kind=AlertKind.ANOMALY,
            severity=anomaly.severity,
            title=f"Metric anomaly on {anomaly.metric}",
            source=anomaly.metric,
            trace_id=trace_id,
            detail=f"value {anomaly.value} scored {anomaly.score} (threshold {anomaly.threshold})",
        )
        by_id[alert.id] = alert

    for drift in drift_alerts:
        alert = Alert(
            id=_alert_id(AlertKind.DRIFT, drift.subject, drift.metric),
            kind=AlertKind.DRIFT,
            severity=drift.severity,
            title=f"Behavioral drift on {drift.subject}",
            source=drift.subject,
            trace_id=trace_id,
            detail=drift.detail,
        )
        by_id[alert.id] = alert

    for event in security_events:
        alert = Alert(
            id=_alert_id(AlertKind.SECURITY_EVENT, event.service, event.id),
            kind=AlertKind.SECURITY_EVENT,
            severity=event.severity,
            title=f"Security event: {event.category}",
            source=event.service,
            trace_id=event.trace_id or trace_id,
            detail=event.detail,
        )
        by_id[alert.id] = alert

    return sorted(by_id.values(), key=lambda alert: (_RANK[alert.severity], alert.id), reverse=True)
