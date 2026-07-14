# Security policy

Report vulnerabilities through GitHub private vulnerability reporting. Include
the affected commit, the scenario, the expected correlation counts, and what was
observed.

This platform ingests synthetic telemetry and runs entirely in-process. It opens
no network connections, ships nothing to a real backend, and executes no
untrusted input. The exporters produce Prometheus, Jaeger, and Loki payloads but
do not push them anywhere.

Detection is deterministic and unsupervised: the modified z-score and PSI are
statistics over the provided series, not a trained model. They are tuned for the
committed scenarios; on real data the thresholds must be calibrated, and a
detection is a signal for a human, not an automated block.

The local API is unauthenticated and must be bound to loopback. Treat correlated
views as sensitive even over synthetic data: they expose service topology and
which requests tripped which controls. Never point this at production telemetry
in a public fork, and never replace the fixtures with real trace or log exports.
