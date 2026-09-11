# Authorization Research Benchmark v8

ERSEC 29.1.1 adds a comparison-ready analysis layer around the deterministic authorization corpus.

## Purpose

The research artifact separates reviewed policy truth from observed ERSEC verdicts and reports:

- precision, recall and F1;
- case coverage;
- requests per true positive;
- replayability;
- false-positive / false-negative analysis;
- uncertainty and observation-unavailable cases;
- relationship and family metadata;
- corpus and manifest fingerprints.

The benchmark remains loopback-only, synthetic, read-only and external-network-free.

## Comparison protocol

External tools should be evaluated against the same reviewed corpus, target variants, case labels and stopping rules. Alert counts are not treated as effectiveness. A comparison must publish missed cases, false positives, untested/unavailable cases, runtime and request cost where those measurements are available.

## Metamorphic controls

The analysis includes representation-level checks that fragments do not alter canonical request identity and that equivalent query parameter orderings canonicalize consistently. These controls do not contact targets.

The artifact is intended as a research scaffold, not an industry benchmark claim.
