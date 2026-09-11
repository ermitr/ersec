# ERSEC 29.1.1 Security Boundary Lab

The Security Boundary Lab is the flagship identity-aware assurance planner for ERSEC 29.1.1. It compiles reviewed identities, roles, tenants, resources and security properties into bounded read-only cases for an authorized harness.

It never stores credential values, contacts a target, expands scope, or performs state-changing actions.

## Compile

```bash
python3 ersec.py --security-boundary-compile examples/security-boundary-lab-29.1.1.json --security-boundary-out boundary-plan.json
```

## Evaluate authorized observations

```bash
python3 ersec.py --security-boundary-evaluate boundary-plan.json examples/security-boundary-evidence-29.1.1.json --security-boundary-out boundary-result.json
```

Missing observations are `not_tested`; incomplete evidence cannot become PASS. A status/field or forbidden-side-effect violation becomes a violation.

## Proof

A controlled baseline PASS followed by a mutation violation can be bound into a proof bundle:

```bash
python3 ersec.py --proof-build case.json baseline.json mutation.json --proof-build-out finding.bundle
python3 ersec.py --proof-verify finding.bundle
```

Proof digests provide integrity only. They are not cryptographic signatures and do not claim unrestricted compromise.
