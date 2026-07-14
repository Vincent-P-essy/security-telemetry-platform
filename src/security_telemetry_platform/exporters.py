"""Export telemetry in the wire formats of common backends.

The point is to prove the model is real OpenTelemetry, not a bespoke shape: the
same spans, metrics, and logs serialize into Prometheus text exposition, a Jaeger
trace document, and a Loki push payload without loss. The backends themselves are
not run here; these functions produce the exact payloads those backends accept.
"""

from __future__ import annotations

from typing import Any

from .models import LogRecord, MetricSeries, Span


def _escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(
        f'{key}="{_escape_label_value(value)}"' for key, value in sorted(labels.items())
    )
    return "{" + inner + "}"


def prometheus_text(series: list[MetricSeries]) -> str:
    """Render metric series in the Prometheus text exposition format."""

    lines: list[str] = []
    for metric in series:
        lines.append(f"# HELP {metric.name} exported security metric ({metric.unit})")
        lines.append(f"# TYPE {metric.name} {metric.type.value}")
        label_str = _labels(metric.labels)
        for point in metric.points:
            timestamp = int(point.epoch * 1000)
            lines.append(f"{metric.name}{label_str} {point.value} {timestamp}")
    return "\n".join(lines) + "\n"


def jaeger_trace(spans: list[Span], trace_id: str) -> dict[str, Any]:
    """Render spans as a Jaeger trace document (query-API shape)."""

    processes: dict[str, dict[str, str]] = {}
    process_ids: dict[str, str] = {}
    jaeger_spans: list[dict[str, Any]] = []
    for span in spans:
        if span.service not in process_ids:
            process_id = f"p{len(process_ids) + 1}"
            process_ids[span.service] = process_id
            processes[process_id] = {"serviceName": span.service}
        references = []
        if span.parent_span_id is not None:
            references.append(
                {"refType": "CHILD_OF", "traceID": trace_id, "spanID": span.parent_span_id}
            )
        tags = [
            {"key": "span.kind", "type": "string", "value": span.kind.value},
            {"key": "otel.status_code", "type": "string", "value": span.status.value},
            *(
                {"key": key, "type": "string", "value": value}
                for key, value in sorted(span.attributes.items())
            ),
        ]
        jaeger_spans.append(
            {
                "traceID": trace_id,
                "spanID": span.span_id,
                "operationName": span.name,
                "references": references,
                "startTime": int(span.start_epoch * 1_000_000),
                "duration": int(span.duration_ms * 1000),
                "tags": tags,
                "processID": process_ids[span.service],
            }
        )
    return {"data": [{"traceID": trace_id, "spans": jaeger_spans, "processes": processes}]}


def loki_push(logs: list[LogRecord]) -> dict[str, Any]:
    """Render log records as a Loki push payload, one stream per (service, severity)."""

    streams: dict[tuple[str, str], list[list[str]]] = {}
    for log in logs:
        key = (log.service, log.severity.value)
        line = log.body if log.trace_id is None else f"{log.body} trace_id={log.trace_id}"
        streams.setdefault(key, []).append([str(int(log.epoch * 1_000_000_000)), line])
    return {
        "streams": [
            {
                "stream": {"service": service, "severity": severity},
                "values": values,
            }
            for (service, severity), values in sorted(streams.items())
        ]
    }
