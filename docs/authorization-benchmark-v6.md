# ERSEC Authorization Benchmark v6

ERSEC 29.1.0 strengthens the controlled authorization benchmark as a measurement artifact rather than a product-performance claim.

## Ground truth and observed verdicts

Operator-reviewed policy truth is stored independently from the observed ERSEC verdict. Scorable cases have reviewed truth of `pass` or `violation` for the vulnerable/fixed variant; ambiguous cases are represented separately.

## Ambiguity taxonomy

The current corpus records explicit reasons for ambiguity:

- `authoritative_response_obscured`
- `field_observation_unavailable`
- `relationship_observer_unavailable`

Ambiguous cases remain visible in reports and are excluded from precision/recall denominators.

## Repetition

The suite runs three repetitions of each vulnerable/fixed variant and records case-verdict stability plus runtime/request-count variance.

## Cost

The benchmark reports total requests, requests per scorable case, and requests per true positive. These are measurements of this fixture implementation only; they are not extrapolated to arbitrary applications.

## Reproducibility

The result contains a canonical corpus digest and a benchmark-report fingerprint. Changing case definitions, truth metadata, relationship metadata, or the measured quality tuple changes the associated digest/fingerprint.

## Safety boundary

The benchmark uses a synthetic loopback fixture, GET requests only, no external targets, no captured credential values, and no intended state-changing probes.
