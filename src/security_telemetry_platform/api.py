"""Local HTTP surface for correlation, scenarios, and exporters."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .exporters import jaeger_trace, loki_push, prometheus_text
from .loader import load_default_scenarios
from .pipeline import run_all, run_scenario
from .reporting import report_to_dict, summarize
from .resources import web_dir
from .scenarios import build_scenario


def create_app() -> FastAPI:
    app = FastAPI(
        title="Security Telemetry Platform",
        version="0.2.0",
        description="Trace/metric/log correlation, anomaly detection, drift, and exporters.",
    )
    specs = load_default_scenarios()

    def _spec(name: str) -> Any:
        spec = next((s for s in specs if s.name == name), None)
        if spec is None:
            raise HTTPException(status_code=404, detail="unknown scenario")
        return spec

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/scenarios")
    def scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {"name": s.name, "description": s.description, "services": list(s.service_chain)}
                for s in specs
            ]
        }

    @app.get("/correlate")
    def correlate_all() -> dict[str, Any]:
        return summarize(run_all(specs))

    @app.get("/correlate/{name}")
    def correlate_one(name: str) -> dict[str, Any]:
        return report_to_dict(run_scenario(_spec(name)))

    @app.get("/export/{name}/prometheus", response_class=PlainTextResponse)
    def export_prometheus(name: str) -> str:
        built = build_scenario(_spec(name))
        return prometheus_text(built.store.metrics)

    @app.get("/export/{name}/jaeger")
    def export_jaeger(name: str) -> dict[str, Any]:
        built = build_scenario(_spec(name))
        return jaeger_trace(built.store.spans_for(built.trace_id), built.trace_id)

    @app.get("/export/{name}/loki")
    def export_loki(name: str) -> dict[str, Any]:
        built = build_scenario(_spec(name))
        return loki_push(built.store.logs_for(built.trace_id))

    directory = web_dir()
    if directory.exists():
        app.mount("/", StaticFiles(directory=str(directory), html=True), name="web")

    return app
