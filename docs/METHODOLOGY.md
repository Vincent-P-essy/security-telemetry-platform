# Methodology

How the measured evidence is produced and what it shows.

## Scenarios and ground truth

Four scenarios in `fixtures/scenarios.yaml` drive the pipeline: two incidents
(credential stuffing, data exfiltration), one behavioral drift with no discrete
spike, and one clean baseline. Each produces a deterministic set of telemetry.
The reviewed correlation counts — anomalies, drift alerts, security alerts, and
correlated spans/logs/events per trace — are committed to
`fixtures/ground-truth.json`, and a test asserts the pipeline reproduces them.

## What each scenario demonstrates

- **credential-stuffing / data-exfiltration** — an anomaly spike, a drift alert, a
  security event, and their spans and logs all resolve to one trace id, producing
  three correlated alerts on a single trace.
- **latency-drift** — the metric never spikes, so the anomaly detector stays
  silent, but the distribution shifts, so drift fires. This is the case a
  point-threshold monitor misses and drift catches.
- **baseline-healthy** — normal traffic: no anomaly, no drift, no event, zero
  alerts. A detector that fired here would be crying wolf.

## Determinism and exports

`sectel benchmark` runs the catalogue `iterations` times and hashes the full
result set — trace ids, alert ids, and every count — each pass.
`deterministic == true` means one identical hash across all passes. It also
re-serializes every scenario to Prometheus, Jaeger, and Loki and checks the
payload shapes (`exports_valid`).

## What the numbers mean and do not mean

They show the correlation, detection, and export logic is correct and
reproducible on the committed scenarios. They do **not** claim the thresholds are
right for real data: the modified z-score and PSI are unsupervised statistics
tuned for these fixtures, and on production telemetry they must be calibrated. A
detection here is a signal for a human, not proof of an attack.

Reproduce locally:

```bash
uv run sectel correlate all
uv run sectel export credential-stuffing --format prometheus
uv run sectel benchmark --iterations 200
```
