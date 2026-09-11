# ERSEC 29.1.1 — Hybrid Oracle & Runtime Control Correlation

ERSEC 29.1.1 now separates semantic response evidence from authoritative downstream evidence.

## Hybrid oracle

Use:

```bash
python ersec.py --hybrid-oracle examples/hybrid-semantic-29.1.1.json examples/hybrid-authoritative-29.1.1.json
```

The example is a combined document, so production use should provide a semantic JSON artifact and an authoritative observation list separately. If semantic and authoritative observers disagree, ERSEC returns `inconclusive` with `observer_conflict`; it never converts disagreement into PASS.

## Runtime controls

```bash
python ersec.py --runtime-control-correlate examples/runtime-control-manifest-29.1.1.json examples/runtime-control-telemetry-29.1.1.json
```

Configured-only evidence is not enforcement proof. Missing, stale, or mismatched telemetry remains an explicit uncertainty state.

This layer is offline and does not contact targets. Runtime adapters can feed OTel/OPA/gateway evidence into the normalized correlation boundary.
