# ERSEC 29.1.0 — Continuous Assurance

ERSEC 29.1.0 can compare successive integrated assurance bundles as a deterministic release regression contract.

## Guarantees

- A previously PASS claim becoming unknown, blocked, inconclusive, or not-tested is a regression for release review.
- A previous violation/uncertain claim becomes an improvement only when the current evidence is explicitly PASS.
- Missing claims are never interpreted as remediation.
- The engine does not contact targets and does not require credentials.
- Contract digests are integrity identifiers, not cryptographic signatures.

## CLI

```bash
python3 ersec.py --continuous-assurance \
  examples/continuous-assurance-before-29.1.0.json \
  examples/continuous-assurance-after-29.1.0.json \
  --continuous-assurance-out continuous-assurance-29.1.0.json
```

Create a release-lineage snapshot:

```bash
python3 ersec.py --assurance-snapshot assurance-loop-29.1.0.json \
  --assurance-snapshot-out assurance-snapshot-29.1.0.json \
  --assurance-release-id 29.1.0
```

The result is intended to feed release gates, historical assurance storage, CI review, and reproducibility evidence.
