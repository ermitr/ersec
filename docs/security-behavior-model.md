# ERSEC Security Behavior Model

The Security Behavior Model is an operator-supplied, declarative description of known application security policy. It is designed for authorized assessments and CI regression control.

## Schema

`ersec-security-behavior-model/1` supports four sections:

- `identities`: name, role, tenant, privilege rank.
- `resources`: stable resource id, absolute URL, owner, tenant, classification, and expected read-only status by identity.
- `invariants`: explicit security properties tied to an identity/resource pair.
- `workflows`: read-only state transitions for graph modeling.

Tokens and cookies are never placed in the model. Provide them separately with the ERSEC CLI/runtime configuration.

## Safe verification

The model verifier executes only `GET`, `HEAD`, and `OPTIONS`. State-changing methods are rejected during validation. Missing credentials produce `not_tested`, not a synthetic allow/deny result.

## Example

See `examples/security-model.example.json`.

Validate it offline:

```bash
ersec --validate-security-model examples/security-model.example.json
```

Run a modeled read-only verification against an authorized target:

```bash
ersec -t https://example.com \
  --security-model security-model.json \
  --behavior-verify-out behavior-verification.json \
  --behavior-state .ersec-security-behavior-state.json
```

## Contract lifecycle

Model-derived contracts are emitted as `draft`. Reviewers should approve only contracts whose expected behavior has been checked against application policy. Use `--contract-approve` to promote selected contracts to `active`, then `--contract-gate` to enforce them in CI.
