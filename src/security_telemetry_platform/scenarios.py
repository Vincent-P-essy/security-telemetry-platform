"""Deterministically synthesize a scenario's telemetry from its spec.

Each scenario becomes a single trace threaded through a chain of services, a
metric series (optionally spiking), audit logs carrying the trace id, and — when
the scenario is an incident — a security event on the same trace. Ids are derived
by hashing the scenario name, so the whole telemetry set is reproducible.

A small deterministic wiggle is added to the metric baseline on purpose: a
perfectly flat baseline has zero median-absolute-deviation, which would blind the
robust anomaly detector to a spike. Real metrics are never flat, and neither are
these.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .models import (
    LogRecord,
    MetricPoint,
    MetricSeries,
    MetricType,
    ScenarioSpec,
    SecurityEvent,
    Severity,
    Span,
    SpanKind,
    SpanStatus,
)
from .telemetry import TelemetryStore

_BASE_EPOCH = 1_700_000_000.0


def _trace_id(name: str) -> str:
    return hashlib.sha256(f"trace|{name}".encode()).hexdigest()[:32]


def _span_id(name: str, index: int) -> str:
    return hashlib.sha256(f"span|{name}|{index}".encode()).hexdigest()[:16]


def primary_service(spec: ScenarioSpec) -> str:
    return spec.service_chain[1] if len(spec.service_chain) > 1 else spec.service_chain[0]


@dataclass(frozen=True)
class BuiltScenario:
    spec: ScenarioSpec
    store: TelemetryStore
    trace_id: str


def build_scenario(spec: ScenarioSpec) -> BuiltScenario:
    store = TelemetryStore()
    trace_id = _trace_id(spec.name)
    incident = spec.security_category is not None

    parent: str | None = None
    for index, service in enumerate(spec.service_chain):
        span_id = _span_id(spec.name, index)
        last = index == len(spec.service_chain) - 1
        status = SpanStatus.ERROR if incident and last else SpanStatus.OK
        store.add_span(
            Span(
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent,
                service=service,
                name=f"{service} handle_request",
                kind=SpanKind.SERVER if index == 0 else SpanKind.CLIENT,
                start_epoch=_BASE_EPOCH + index,
                duration_ms=round(12.0 + index * 4.5, 3),
                status=status,
                attributes={"http.route": "/api/v1/resource", "span.index": str(index)},
            )
        )
        store.add_log(
            LogRecord(
                epoch=_BASE_EPOCH + index,
                severity=Severity.INFO,
                service=service,
                body=f"{service} processed request",
                trace_id=trace_id,
                attributes={"span_id": span_id},
            )
        )
        parent = span_id

    step = max(0.5, spec.baseline_value * 0.05)
    points: list[MetricPoint] = []
    for k in range(spec.length):
        value = spec.baseline_value + (k % 5) * step
        if spec.spike_at is not None and k == spec.spike_at and spec.spike_value is not None:
            value = spec.spike_value
        points.append(MetricPoint(epoch=_BASE_EPOCH + k, value=round(value, 3)))
    store.add_metric(
        MetricSeries(
            name=spec.anomaly_metric,
            type=MetricType.COUNTER if spec.anomaly_metric.endswith("_total") else MetricType.GAUGE,
            labels={"service": primary_service(spec), "trace_id": trace_id},
            points=tuple(points),
        )
    )

    if incident and spec.security_category is not None:
        store.add_security_event(
            SecurityEvent(
                id=f"{spec.name}-event",
                epoch=_BASE_EPOCH + spec.length,
                category=spec.security_category,
                severity=spec.security_severity,
                service=spec.service_chain[-1],
                trace_id=trace_id,
                detail=f"{spec.security_category} detected on trace {trace_id}",
            )
        )
        store.add_log(
            LogRecord(
                epoch=_BASE_EPOCH + spec.length,
                severity=Severity.HIGH,
                service=spec.service_chain[-1],
                body=f"security control fired: {spec.security_category}",
                trace_id=trace_id,
                attributes={"category": spec.security_category},
            )
        )

    return BuiltScenario(spec=spec, store=store, trace_id=trace_id)
