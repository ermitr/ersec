# ERSEC 29.1.0 — Stateful Security Behavior Assurance

ERSEC 29.1.0 adds a bounded stateful assurance compiler for reviewed business-flow invariants.

## Trust boundary

The compiler and evaluator are offline. They do not contact targets, accept credential material, or perform destructive actions. An authorized harness owns execution and supplies redacted evidence.

## Workflow model

A workflow declares states, transitions, roles and explicit invariants. ERSEC generates a bounded scenario inventory including baseline and safe negative-path categories:

- skip prerequisite
- reverse transition
- replay terminal action
- tenant switch
- object rebind
- stale/revoked session context

Generated scenarios are hypotheses/test obligations, not automatic findings.

## Evidence semantics

Evidence can be `pass`, `violation`, `inconclusive`, `not_tested`, `blocked`, or `unmodeled`. Missing evidence is `not_tested`; an unavailable authoritative oracle is `inconclusive`.

Trace IDs, policy-decision IDs and service revisions are correlation metadata only. They do not become proof merely because they exist.

## Safety

State-changing execution remains outside this compiler and requires an authorized harness with scope, rate, timeout and cleanup controls. Production enforcement is not enabled by this feature.

## CLI

```bash
ersec --assurance-flow-compile examples/stateful-business-flow-29.1.0.yaml \
  --assurance-flow-out stateful-plan-29.1.0.json

ersec --assurance-flow-evaluate stateful-plan-29.1.0.json \
  examples/stateful-evidence-29.1.0.json \
  --assurance-flow-result-out stateful-result-29.1.0.json
```
