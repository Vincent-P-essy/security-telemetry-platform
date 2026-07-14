"""Deterministic benchmark over the scenario catalogue.

Runs every scenario ``iterations`` times, checks the correlation counts against
the committed ground truth, confirms the full result set is byte-identical across
passes via a single stable hash, verifies each scenario's telemetry still exports
to Prometheus/Jaeger/Loki, and measures wall time. Everything downstream of the
seeded telemetry is deterministic, so the hash never varies.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .exporters import jaeger_trace, loki_push, prometheus_text
from .loader import load_default_scenarios
from .models import ScenarioSpec
from .pipeline import ScenarioReport, ground_truth, run_all
from .resources import packaged_path
from .scenarios import build_scenario


@dataclass(frozen=True)
class BenchmarkResult:
    iterations: int
    scenarios: int
    incidents: int
    total_alerts: int
    matched: int
    ground_truth_verified: bool
    deterministic: bool
    exports_valid: bool
    report_hash: str
    latency_pass_p50_ms: float
    latency_pass_p95_ms: float
    elapsed_seconds: float
    source_revision: str
    source_tree_state: str


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[rank], 4)


def _outcome_map(reports: list[ScenarioReport]) -> dict[str, object]:
    return {
        report.name: {
            "counts": report.counts(),
            "trace_id": report.trace_id,
            "alert_ids": sorted(alert.id for alert in report.alerts),
        }
        for report in reports
    }


def _hash(payload: dict[str, object]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def committed_ground_truth() -> dict[str, dict[str, int]]:
    data: dict[str, dict[str, int]] = json.loads(
        packaged_path("ground-truth.json").read_text(encoding="utf-8")
    )
    return data


def _exports_valid(specs: tuple[ScenarioSpec, ...]) -> bool:
    for spec in specs:
        built = build_scenario(spec)
        prom = prometheus_text(built.store.metrics)
        jaeger = jaeger_trace(built.store.spans_for(built.trace_id), built.trace_id)
        loki = loki_push(built.store.logs_for(built.trace_id))
        if "# TYPE" not in prom:
            return False
        if not jaeger["data"][0]["spans"]:
            return False
        if not loki["streams"]:
            return False
    return True


def benchmark(iterations: int = 100) -> BenchmarkResult:
    specs = load_default_scenarios()
    declared = ground_truth(specs)
    committed = committed_ground_truth()
    durations_ms: list[float] = []
    hashes: set[str] = set()
    matched = 0
    incidents = 0
    total_alerts = 0
    started = time.perf_counter()

    for iteration in range(iterations):
        pass_start = time.perf_counter()
        reports = run_all(specs)
        durations_ms.append((time.perf_counter() - pass_start) * 1000)
        hashes.add(_hash(_outcome_map(reports)))
        if iteration == 0:
            incidents = sum(1 for r in reports if r.view.security_events)
            total_alerts = sum(len(r.alerts) for r in reports)
            matched = sum(
                1 for r in reports if r.counts() == committed.get(r.name) == declared[r.name]
            )

    elapsed = time.perf_counter() - started
    return BenchmarkResult(
        iterations=iterations,
        scenarios=len(declared),
        incidents=incidents,
        total_alerts=total_alerts,
        matched=matched,
        ground_truth_verified=matched == len(declared),
        deterministic=len(hashes) == 1,
        exports_valid=_exports_valid(specs),
        report_hash=next(iter(hashes)) if hashes else "",
        latency_pass_p50_ms=_percentile(durations_ms, 50),
        latency_pass_p95_ms=_percentile(durations_ms, 95),
        elapsed_seconds=round(elapsed, 4),
        source_revision=os.environ.get("SECTEL_SOURCE_REVISION", "unknown"),
        source_tree_state=os.environ.get("SECTEL_SOURCE_TREE_STATE", "unknown"),
    )


def write_benchmark(out_dir: Path, result: BenchmarkResult) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "benchmark.json"
    path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
