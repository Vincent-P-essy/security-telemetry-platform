from __future__ import annotations

from security_telemetry_platform.correlation import correlate
from security_telemetry_platform.exporters import jaeger_trace, loki_push, prometheus_text
from security_telemetry_platform.loader import load_default_scenarios
from security_telemetry_platform.models import (
    LogRecord,
    MetricPoint,
    MetricSeries,
    Span,
    SpanKind,
)
from security_telemetry_platform.scenarios import build_scenario
from security_telemetry_platform.telemetry import TelemetryStore

TRACE = "0" * 32
OTHER = "1" * 32


def _store() -> TelemetryStore:
    store = TelemetryStore()
    store.add_span(
        Span(
            trace_id=TRACE,
            span_id="a" * 16,
            service="gateway",
            name="in",
            kind=SpanKind.SERVER,
            start_epoch=1,
            duration_ms=5,
        )
    )
    store.add_span(
        Span(
            trace_id=TRACE,
            span_id="b" * 16,
            parent_span_id="a" * 16,
            service="auth",
            name="check",
            start_epoch=2,
            duration_ms=3,
        )
    )
    store.add_span(
        Span(
            trace_id=OTHER,
            span_id="c" * 16,
            service="other",
            name="x",
            start_epoch=1,
            duration_ms=1,
        )
    )
    store.add_log(LogRecord(epoch=1, service="gateway", body="hit", trace_id=TRACE))
    store.add_log(LogRecord(epoch=1, service="other", body="noise", trace_id=OTHER))
    store.add_metric(
        MetricSeries(name="m", labels={"trace_id": TRACE}, points=(MetricPoint(epoch=1, value=1),))
    )
    return store


def test_correlate_gathers_only_matching_trace() -> None:
    view = correlate(_store(), TRACE)
    assert len(view.spans) == 2
    assert view.services == ("gateway", "auth")
    assert len(view.logs) == 1
    assert view.metrics == ("m",)


def test_prometheus_exposition_format() -> None:
    store = _store()
    text = prometheus_text(store.metrics)
    assert "# HELP m" in text
    assert "# TYPE m gauge" in text
    assert 'm{trace_id="' in text


def test_jaeger_trace_shape() -> None:
    store = _store()
    doc = jaeger_trace(store.spans_for(TRACE), TRACE)
    spans = doc["data"][0]["spans"]
    assert len(spans) == 2
    child = next(s for s in spans if s["spanID"] == "b" * 16)
    assert child["references"][0]["refType"] == "CHILD_OF"
    assert doc["data"][0]["processes"]


def test_loki_push_shape() -> None:
    store = _store()
    payload = loki_push(store.logs_for(TRACE))
    assert payload["streams"]
    stream = payload["streams"][0]
    assert stream["stream"]["service"] == "gateway"
    assert "trace_id=" in stream["values"][0][1]


def test_exporters_on_real_scenario() -> None:
    spec = next(s for s in load_default_scenarios() if s.name == "credential-stuffing")
    built = build_scenario(spec)
    assert "# TYPE auth_failures_total counter" in prometheus_text(built.store.metrics)
    assert jaeger_trace(built.store.spans_for(built.trace_id), built.trace_id)["data"][0]["spans"]
