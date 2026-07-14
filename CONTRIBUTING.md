# Contributing

Every change to detection, correlation, or the exporters needs:

1. a positive test (a spike is flagged, drift is detected, an incident correlates
   every signal by trace id);
2. a negative test (a flat or gently varying series is not anomalous, similar
   distributions do not drift, a benign scenario raises no alerts);
3. a determinism check: the benchmark must reproduce a single stable hash;
4. an exporter shape test when a payload format changes;
5. a ground-truth review when correlation counts change, kept in sync with
   `fixtures/ground-truth.json` (a test enforces this).

Keep detection robust and deterministic: the anomaly detector must survive a
zero-MAD (flat) series, and PSI must survive empty bins on small samples. Every
security signal must carry the trace id so it correlates; an alert without a
trace id cannot be tied back to its request.

Run before submitting:

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
sha256sum --check benchmarks/reference/inputs.sha256
docker compose config --quiet
docker build -t security-telemetry-platform:test .
```

Do not commit real telemetry, credentials, or generated co-author trailers.
