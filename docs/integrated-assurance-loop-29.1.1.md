# ERSEC 29.1.1 — Integrated Assurance Loop

ERSEC 29.1.1 now exposes a deterministic orchestration layer that connects the major assurance primitives into one evidence bundle:

`reviewed policy → unified inventory → assurance cells → disposable fixture truth → stateful plan → metamorphic evidence → controlled counterfactual → Security Reality Fabric → Assurance Kernel → Assurance Intelligence`

## Safety boundary

The orchestration layer is offline. It does not contact a user-supplied target, create accounts, store credential values, execute exploits, or perform destructive actions. A future authorized harness may consume the generated plans and return evidence; the deterministic layers treat missing evidence as `not_tested`, `inconclusive`, `blocked`, or `unknown` rather than PASS.

## CLI

```bash
python3 ersec.py \
  --assurance-loop /tmp/ersec-29.1.1-assurance.json \
  --assurance-loop-policy examples/security-behavior-policy-29.1.1.yaml \
  --assurance-loop-inventory examples/api-behavior-inventory-29.1.1.json \
  --assurance-loop-stateful examples/stateful-business-flow-29.1.1.yaml \
  --assurance-loop-metamorphic examples/metamorphic-security-29.1.1.json \
  --assurance-loop-baseline examples/counterfactual-baseline-29.1.1.json \
  --assurance-loop-mutated examples/counterfactual-mutated-29.1.1.json
```

The output is a single evidence bundle containing the compiled plan, fixture oracle, stateful plan, metamorphic result, counterfactual result, reality model, proof decision, and next-best-assurance analysis.

## Interpretation

A `PASS` from an individual layer proves only that layer's declared property. The integrated bundle can remain `BLOCKED` because an unrelated required proof obligation lacks sufficient positive evidence. This is intentional: ERSEC 29.1.1 is designed to expose proof debt instead of converting incomplete coverage into a green release.

The bundle's `integrated_digest` is a content digest for reproducibility. It is not a cryptographic signature or release attestation.
