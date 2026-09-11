# Multi-Tenant REST Authorization Benchmark v1

This fixture is a deterministic local benchmark for ERSEC's semantic authorization wedge.

It contains a vulnerable and fixed variant of a small multi-tenant REST behavior model.
The benchmark uses only loopback traffic, synthetic identities, synthetic objects, and
read-only `GET` requests.

Run:

```bash
ersec --authorization-benchmark results.json
```

The resulting artifact records the operator-reviewed oracle, vulnerable/fixed variants,
coverage, precision, recall, F1, request count, runtime, and reproducibility constraints.
