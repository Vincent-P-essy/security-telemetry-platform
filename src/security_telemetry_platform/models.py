"""Typed telemetry model, following the OpenTelemetry data model.

Traces, metrics, and logs use the OpenTelemetry vocabulary (trace/span ids,
span kinds and status, metric instruments, log severity) so the exporters can
emit real Prometheus, Jaeger, and Loki payloads. On top of that sits a thin
security layer — security events and alerts — all keyed by ``trace_id`` so one
suspicious request can be followed across every signal. Models are frozen and
reject unknown fields.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

TRACE_ID = r"^[a-f0-9]{32}$"
SPAN_ID = r"^[a-f0-9]{16}$"
IDENTIFIER = r"^[a-z0-9][a-z0-9_.:-]{0,63}$"


class SpanKind(StrEnum):
    SERVER = "server"
    CLIENT = "client"
    INTERNAL = "internal"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class SpanStatus(StrEnum):
    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


class MetricType(StrEnum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertKind(StrEnum):
    ANOMALY = "anomaly"
    DRIFT = "drift"
    SECURITY_EVENT = "security_event"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Span(Frozen):
    trace_id: str = Field(pattern=TRACE_ID)
    span_id: str = Field(pattern=SPAN_ID)
    parent_span_id: str | None = Field(default=None, pattern=SPAN_ID)
    service: str = Field(pattern=IDENTIFIER)
    name: str = Field(max_length=120)
    kind: SpanKind = SpanKind.INTERNAL
    start_epoch: float = Field(ge=0)
    duration_ms: float = Field(ge=0)
    status: SpanStatus = SpanStatus.OK
    attributes: dict[str, str] = Field(default_factory=dict)


class MetricPoint(Frozen):
    epoch: float = Field(ge=0)
    value: float


class MetricSeries(Frozen):
    name: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,80}$")
    type: MetricType = MetricType.GAUGE
    unit: str = Field(default="1", max_length=32)
    labels: dict[str, str] = Field(default_factory=dict)
    points: tuple[MetricPoint, ...] = Field(default=(), max_length=100_000)

    @property
    def values(self) -> tuple[float, ...]:
        return tuple(point.value for point in self.points)


class LogRecord(Frozen):
    epoch: float = Field(ge=0)
    severity: Severity = Severity.INFO
    service: str = Field(pattern=IDENTIFIER)
    body: str = Field(max_length=500)
    trace_id: str | None = Field(default=None, pattern=TRACE_ID)
    attributes: dict[str, str] = Field(default_factory=dict)


class SecurityEvent(Frozen):
    id: str = Field(pattern=IDENTIFIER)
    epoch: float = Field(ge=0)
    category: str = Field(pattern=IDENTIFIER)
    severity: Severity = Severity.MEDIUM
    service: str = Field(pattern=IDENTIFIER)
    trace_id: str | None = Field(default=None, pattern=TRACE_ID)
    detail: str = Field(max_length=300)
    attributes: dict[str, str] = Field(default_factory=dict)


class Anomaly(Frozen):
    metric: str
    method: str
    at_epoch: float
    value: float
    score: float
    threshold: float
    severity: Severity


class DriftAlert(Frozen):
    subject: str
    metric: str
    score: float
    threshold: float
    severity: Severity
    detail: str = Field(max_length=200)


class Alert(Frozen):
    id: str
    kind: AlertKind
    severity: Severity
    title: str = Field(max_length=200)
    source: str
    trace_id: str | None = None
    detail: str = Field(default="", max_length=300)


class ScenarioSpec(Frozen):
    """Parameters that deterministically generate one scenario's telemetry."""

    name: str = Field(pattern=IDENTIFIER)
    description: str = Field(max_length=300)
    service_chain: tuple[str, ...] = Field(min_length=1, max_length=16)
    anomaly_metric: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,80}$")
    baseline_value: float = Field(ge=0)
    length: int = Field(default=12, ge=3, le=1000)
    spike_at: int | None = Field(default=None, ge=0)
    spike_value: float | None = Field(default=None, ge=0)
    drift_metric: str = Field(pattern=r"^[a-z_][a-z0-9_]{0,80}$")
    drift_baseline: tuple[float, ...] = Field(min_length=1, max_length=10_000)
    drift_current: tuple[float, ...] = Field(min_length=1, max_length=10_000)
    security_category: str | None = Field(default=None, pattern=IDENTIFIER)
    security_severity: Severity = Severity.MEDIUM
    expect_anomaly: bool = False
    expect_drift: bool = False
    expect_security_alert: bool = False


class CorrelatedView(Frozen):
    """Everything sharing one trace id, assembled into a single view."""

    trace_id: str
    services: tuple[str, ...]
    spans: tuple[Span, ...]
    logs: tuple[LogRecord, ...]
    security_events: tuple[SecurityEvent, ...]
    metrics: tuple[str, ...]
    alerts: tuple[Alert, ...]

    @property
    def error_spans(self) -> int:
        return sum(1 for span in self.spans if span.status is SpanStatus.ERROR)
