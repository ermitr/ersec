# ERSEC 29.1.1 — Authoritative Observers and Provenance

ERSEC 29.1.1 can normalize supplied OTel-like spans, OPA decisions, and API-gateway decisions into a common authoritative observation contract. The adapter is parsing-only: it does not contact telemetry systems.

## Observer boundary

An authoritative observation should carry a trace identifier and, when available, a service revision. A supplied expected revision is enforced conservatively. Missing or mismatched revision evidence is rejected from trace correlation rather than treated as proof.

Conflicting authoritative observations for the same trace produce `inconclusive`. Agreement on `pass` or `violation` is preserved for downstream hybrid-oracle evaluation.

```bash
python ersec.py --observer-adapt examples/authoritative-observers-29.1.1.json --observer-trace-verify examples/authoritative-observers-29.1.1.json --observer-expected-revision rev-29
```

## Provenance

Release evidence can be converted into an in-toto/SLSA-shaped provenance statement:

```bash
python ersec.py --provenance release-evidence-29.1.1.json --provenance-out provenance-29.1.1.json
python ersec.py --verify-provenance provenance-29.1.1.json
```

The statement is integrity-bound with SHA-256. It is **not signed**. A digest is not a cryptographic signature. A trusted build system or external signer must perform the actual signing/attestation operation before the statement is treated as a trusted provenance attestation.

The deterministic ERSEC trust boundary therefore remains:

`observed evidence → normalized observer record → assurance decision → release evidence → provenance statement → external signature`

No credential values are accepted or emitted by these adapters.
