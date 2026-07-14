"""Smoke-test the installed wheel from outside the source checkout."""

from __future__ import annotations

from security_telemetry_platform.benchmark import committed_ground_truth
from security_telemetry_platform.pipeline import ground_truth, run_all


def main() -> int:
    if ground_truth() != committed_ground_truth():
        print("ground truth drift")
        return 1
    reports = run_all()
    incidents = sum(1 for r in reports if r.view.security_events)
    alerts = sum(len(r.alerts) for r in reports)
    print(f"ok: {len(reports)} scenarios correlated, {incidents} incidents, {alerts} alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
