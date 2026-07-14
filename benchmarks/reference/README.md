# Reviewed reference run

`reference-run.json` is a committed benchmark over the scenario catalogue,
produced by:

```bash
SECTEL_SOURCE_REVISION=reference SECTEL_SOURCE_TREE_STATE=clean-checkout \
  uv run sectel benchmark --iterations 200 --out benchmarks/reference
```

`inputs.sha256` pins the scenario definitions and the correlation ground truth.
CI verifies them with `sha256sum --check benchmarks/reference/inputs.sha256`.

## What the run establishes

- **Correctness.** All four scenarios reproduce their reviewed correlation counts
  — anomalies, drift, security alerts, and correlated spans/logs/events — matching
  `fixtures/ground-truth.json` (`ground_truth_verified == true`). Two are
  incidents; one drifts without a spike; one is clean.
- **Determinism.** Every pass produces a byte-identical result set — trace ids,
  alert ids, counts — collapsed to one `report_hash` (`deterministic == true`).
- **Real exporters.** Every scenario's telemetry still serializes to Prometheus,
  Jaeger, and Loki payloads (`exports_valid == true`).

Latency is machine dependent and not asserted in CI; only correctness,
determinism, export validity, and input integrity are.
