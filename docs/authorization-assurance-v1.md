# Authorization Assurance v1

ERSEC 29.1.1 defines a deterministic authorization matrix and remediation comparison boundary for the multi-tenant assurance wedge.

## Matrix

`--authorization-matrix-v2` exports one cell for each modeled identity/resource/method combination. Each cell records the actor/resource relationship (`owner`, `same_tenant`, or `cross_tenant`) and expected semantic response constraints without storing credential values.

## Credential references

`--authorization-credentials` validates opaque operator references only. Environment references must use uppercase variable names. ERSEC never reads the referenced secret during validation.

## Remediation

`--authorization-remediation AFTER --authorization-baseline BEFORE` compares previously observed violations with a later assurance run. A former violation is marked resolved only when the later run contains the same case with an explicit `pass` verdict. `not_tested`, `blocked`, or missing cases remain unverified.

This is intentionally narrower than a global claim that an authorization defect is fixed.
