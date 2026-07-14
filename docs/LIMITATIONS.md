# Limitations

This is a portfolio-grade prototype. It demonstrates how to instrument *security*
signals with OpenTelemetry context and correlate them, over synthetic telemetry,
not a production observability platform.

- **Synthetic telemetry.** Traces, metrics, logs, and security events are
  generated from scenario specs. There is no live instrumentation, collector, or
  ingestion from real services.
- **Backends are not run.** The exporters produce genuine Prometheus, Jaeger, and
  Loki payloads, but nothing is pushed to a running Prometheus, Tempo, Loki, or
  Grafana. Tempo ingests OTLP; only its Jaeger-compatible read shape is shown.
- **Unsupervised, uncalibrated detection.** The modified z-score and PSI are
  statistics over the provided series with fixed thresholds tuned for these
  scenarios. On real data the thresholds must be calibrated, and detections are
  signals for a human, not automated blocks.
- **Correlation is by trace id only.** Real correlation also uses spans links,
  baggage, resource attributes, and exemplars; this models the single most
  important join (trace id) and not the rest.
- **No sampling, no cardinality control, no retention.** Production telemetry
  pipelines must handle tail sampling, metric cardinality, and storage; none of
  that is modeled.
- **Point-in-time metrics.** Metric series are short fixtures, not real
  time-series with irregular timestamps, resets, or histograms with buckets.
- **Local API.** Unauthenticated and for loopback only.

The value is showing the *pattern*: give every security signal the same trace
context as the request that caused it, and one suspicious request becomes one
story instead of four disconnected tools. See the [architecture](ARCHITECTURE.md)
and [methodology](METHODOLOGY.md).
