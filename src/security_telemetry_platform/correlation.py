"""Assemble every signal that shares a trace id into one view.

This is the payoff of instrumenting security signals with the same trace context
as the request that caused them: a single ``trace_id`` links the ingress span,
the metric series that spiked, the audit log lines, the security event, and the
alerts. The correlated view is what an analyst reads instead of pivoting across
four tools.
"""

from __future__ import annotations

from .models import Alert, CorrelatedView
from .telemetry import TelemetryStore


def correlate(
    store: TelemetryStore, trace_id: str, alerts: tuple[Alert, ...] = ()
) -> CorrelatedView:
    """Return everything in ``store`` that shares ``trace_id``."""

    spans = store.spans_for(trace_id)
    spans.sort(key=lambda span: (span.start_epoch, span.span_id))
    services: dict[str, None] = {}
    for span in spans:
        services.setdefault(span.service, None)

    logs = store.logs_for(trace_id)
    logs.sort(key=lambda log: log.epoch)
    events = store.events_for(trace_id)
    metrics = tuple(series.name for series in store.metrics_for(trace_id))
    trace_alerts = tuple(alert for alert in alerts if alert.trace_id == trace_id)

    return CorrelatedView(
        trace_id=trace_id,
        services=tuple(services),
        spans=tuple(spans),
        logs=tuple(logs),
        security_events=tuple(events),
        metrics=metrics,
        alerts=trace_alerts,
    )
