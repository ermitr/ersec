# ERSEC 29.1.1 — Reproducible Assurance Benchmark Laboratory

The 29.1.1 benchmark laboratory turns the roadmap's public/release/held-out corpus model into an executable, loopback-only evaluation harness. It measures authorization behavior against explicit reviewed ground truth and reports uncertainty instead of converting missing evidence into PASS.

## Run

```bash
python3 ersec.py --assurance-benchmark-run artifacts/assurance-benchmark-29.1.1.json
```

The laboratory starts only ERSEC's synthetic loopback fixture. It does not contact a user-supplied target, does not perform destructive actions, and does not capture credential values.

## Corpus tiers

Cases are assigned by a deterministic SHA-256 bucket into: **public**, **release**, and **held_out**. The split is part of the result manifest and therefore can be independently reproduced from the same corpus.

The held-out tier is evaluated by the same harness but is kept separate from the public/release scorecards. The benchmark does not use held-out observations as implementation rules.

## Metrics

The lab reports TP, FP, FN, TN, precision, recall, F1, false-positive rate, inconclusive count, request cost, runtime, fixture cleanup, and mutation adequacy. Ambiguous cases remain excluded from precision/recall denominators.

Mutation adequacy is an **assurance-test quality metric**, not a vulnerability-detection rate. Surviving mutants are surfaced as coverage gaps rather than hidden.

## Evidence/reproducibility

Every artifact records the ERSEC version, environment, corpus digest, tier membership, suite fingerprints, fixture lifecycle, mutation audit digest, observer-conflict probe, timing, and a reproducibility digest. The full roadmap evidence contract is listed in the output.

## Interpretation

A green benchmark result is evidence for the included corpus and configuration only. It is not proof of absence of vulnerabilities and is not a competitor benchmark.
