"""Serialize pipeline reports and telemetry exports into review artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .exporters import jaeger_trace, loki_push, prometheus_text
from .models import CorrelatedView
from .pipeline import ScenarioReport
from .telemetry import TelemetryStore


def view_to_dict(view: CorrelatedView) -> dict[str, Any]:
    return {
        "trace_id": view.trace_id,
        "services": list(view.services),
        "spans": [
            {"service": s.service, "name": s.name, "status": s.status.value, "span_id": s.span_id}
            for s in view.spans
        ],
        "logs": [{"service": log.service, "body": log.body} for log in view.logs],
        "security_events": [
            {"category": e.category, "severity": e.severity.value} for e in view.security_events
        ],
        "metrics": list(view.metrics),
        "alerts": [
            {"id": a.id, "kind": a.kind.value, "severity": a.severity.value, "title": a.title}
            for a in view.alerts
        ],
    }


def report_to_dict(report: ScenarioReport) -> dict[str, Any]:
    return {
        "name": report.name,
        "trace_id": report.trace_id,
        "counts": report.counts(),
        "anomalies": [
            {"metric": a.metric, "value": a.value, "score": a.score, "severity": a.severity.value}
            for a in report.anomalies
        ],
        "drift_alerts": [
            {
                "subject": d.subject,
                "metric": d.metric,
                "score": d.score,
                "severity": d.severity.value,
            }
            for d in report.drift_alerts
        ],
        "correlated": view_to_dict(report.view),
    }


def summarize(reports: list[ScenarioReport]) -> dict[str, Any]:
    return {
        "scenarios": len(reports),
        "total_alerts": sum(len(r.alerts) for r in reports),
        "incidents": sum(1 for r in reports if r.view.security_events),
        "results": [report_to_dict(r) for r in reports],
    }


def render_markdown(reports: list[ScenarioReport]) -> str:
    lines = [
        "# Security telemetry correlation",
        "",
        "| Scenario | Trace | Anomalies | Drift | Security | Alerts |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for report in reports:
        counts = report.counts()
        lines.append(
            f"| {report.name} | `{report.trace_id[:12]}` | {counts['anomalies']} | "
            f"{counts['drift_alerts']} | {counts['security_alerts']} | {counts['total_alerts']} |"
        )
    return "\n".join(lines) + "\n"


def export_bundle(store: TelemetryStore, trace_id: str) -> dict[str, Any]:
    """Render a store's telemetry into Prometheus, Jaeger, and Loki payloads."""

    return {
        "prometheus": prometheus_text(store.metrics),
        "jaeger": jaeger_trace(store.spans_for(trace_id), trace_id),
        "loki": loki_push(store.logs_for(trace_id)),
    }


def write_report(out_dir: Path, reports: list[ScenarioReport]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "correlation.json"
    md_path = out_dir / "correlation.md"
    json_path.write_text(
        json.dumps(summarize(reports), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(reports), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}
