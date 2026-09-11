# ERSEC 29.1.0 — Remediation Verification Loop

ERSEC 29.1.0 now verifies remediation at the **security-property** level rather than treating alert disappearance as resolution.

## Contract

`--remediation-contracts` produces stable property identities. `--remediation-verify CONTRACTS EVIDENCE` then requires fresh positive evidence for each contract.

Verdicts:

- `VERIFIED` — fresh evidence explicitly satisfies the contract.
- `ALREADY_PASS` — the property was already passing in the supplied baseline; this is not credited as remediation.
- `NOT_RESOLVED` — the observation is missing, violating, inconclusive, blocked, unknown, or not tested.
- `BLOCKED` — required evidence structure is incomplete.

A disappeared observation is never remediation. An evidence digest is an integrity reference, not a signature.

## Safety

The verifier is offline and does not contact targets, create credentials, execute exploits, or perform destructive actions. It consumes evidence produced by an authorized assurance harness.

## Example

```bash
python ersec.py --remediation-verify \
  examples/remediation-contract-input-29.1.0.json \
  examples/remediation-verification-evidence-29.1.0.json \
  --remediation-verify-out remediation-verification-29.1.0.json
```
