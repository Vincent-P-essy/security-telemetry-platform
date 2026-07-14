"""An in-memory telemetry store indexed for correlation.

The store holds spans, metric series, logs, and security events and answers the
question the security layer cares about: *given a trace id, what happened?* It
indexes every signal that carries a ``trace_id`` so a correlated view can be
assembled in one pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import LogRecord, MetricSeries, SecurityEvent, Span


@dataclass
class TelemetryStore:
    spans: list[Span] = field(default_factory=list)
    metrics: list[MetricSeries] = field(default_factory=list)
    logs: list[LogRecord] = field(default_factory=list)
    security_events: list[SecurityEvent] = field(default_factory=list)

    def add_span(self, span: Span) -> None:
        self.spans.append(span)

    def add_metric(self, series: MetricSeries) -> None:
        self.metrics.append(series)

    def add_log(self, record: LogRecord) -> None:
        self.logs.append(record)

    def add_security_event(self, event: SecurityEvent) -> None:
        self.security_events.append(event)

    def trace_ids(self) -> list[str]:
        seen: dict[str, None] = {}
        for span in self.spans:
            seen.setdefault(span.trace_id, None)
        return list(seen)

    def spans_for(self, trace_id: str) -> list[Span]:
        return [span for span in self.spans if span.trace_id == trace_id]

    def logs_for(self, trace_id: str) -> list[LogRecord]:
        return [log for log in self.logs if log.trace_id == trace_id]

    def events_for(self, trace_id: str) -> list[SecurityEvent]:
        return [event for event in self.security_events if event.trace_id == trace_id]

    def metrics_for(self, trace_id: str) -> list[MetricSeries]:
        return [series for series in self.metrics if series.labels.get("trace_id") == trace_id]

    def metric(self, name: str) -> MetricSeries | None:
        return next((series for series in self.metrics if series.name == name), None)
