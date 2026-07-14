"""Command-line interface for the security telemetry platform."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import uvicorn

from .benchmark import benchmark, write_benchmark
from .exporters import jaeger_trace, loki_push, prometheus_text
from .loader import load_default_scenarios
from .pipeline import run_all, run_scenario
from .reporting import report_to_dict, summarize, write_report
from .scenarios import build_scenario

_EXPORTERS = ("prometheus", "jaeger", "loki")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sectel", description="Security telemetry platform")
    commands = root.add_subparsers(dest="command", required=True)

    correlate = commands.add_parser(
        "correlate", help="run one scenario or all and show correlation"
    )
    correlate.add_argument("scenario", nargs="?", default="all")

    export = commands.add_parser("export", help="export a scenario's telemetry to a backend format")
    export.add_argument("scenario")
    export.add_argument("--format", choices=_EXPORTERS, required=True)

    report = commands.add_parser("report", help="run all scenarios and write a report")
    report.add_argument("--out", type=Path, default=Path("reports"))

    run_benchmark = commands.add_parser("benchmark", help="measure the catalogue")
    run_benchmark.add_argument("--iterations", type=int, default=100)
    run_benchmark.add_argument("--out", type=Path, default=Path("reports"))

    serve = commands.add_parser("serve", help="start the local API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    return root


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    specs = load_default_scenarios()

    if args.command == "correlate":
        if args.scenario == "all":
            _print(summarize(run_all(specs)))
            return 0
        spec = next((s for s in specs if s.name == args.scenario), None)
        if spec is None:
            print(f"unknown scenario: {args.scenario}")
            return 2
        _print(report_to_dict(run_scenario(spec)))
        return 0

    if args.command == "export":
        spec = next((s for s in specs if s.name == args.scenario), None)
        if spec is None:
            print(f"unknown scenario: {args.scenario}")
            return 2
        built = build_scenario(spec)
        if args.format == "prometheus":
            print(prometheus_text(built.store.metrics), end="")
        elif args.format == "jaeger":
            _print(jaeger_trace(built.store.spans_for(built.trace_id), built.trace_id))
        else:
            _print(loki_push(built.store.logs_for(built.trace_id)))
        return 0

    if args.command == "report":
        paths = write_report(args.out, run_all(specs))
        _print({key: str(path) for key, path in paths.items()})
        return 0

    if args.command == "benchmark":
        measured = benchmark(iterations=args.iterations)
        path = write_benchmark(args.out, measured)
        _print({"benchmark": str(path), **asdict(measured)})
        return 0

    if args.command == "serve":
        uvicorn.run(
            "security_telemetry_platform.api:create_app",
            host=args.host,
            port=args.port,
            factory=True,
            log_level="info",
        )
        return 0

    return 2  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
