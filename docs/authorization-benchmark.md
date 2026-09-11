# Authorization Benchmark Laboratory

ERSEC 29.1.0 introduces the first executable ground-truth benchmark for the
security-behavior assurance wedge.

The benchmark is deliberately narrow:

- loopback only;
- synthetic identities and objects;
- read-only GET requests;
- deterministic vulnerable and fixed variants;
- operator-reviewed expected violations;
- no external target interaction.

Run it with:

```bash
ersec --authorization-benchmark authorization-benchmark.json
```

The artifact reports the vulnerable and fixed variants separately and includes
precision, recall, F1, coverage, request count, runtime, and reproducibility
metadata.

A perfect score here means the benchmark oracle was reproduced correctly. It
does **not** imply that ERSEC has achieved perfect accuracy against arbitrary
applications.
