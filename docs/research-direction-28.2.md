# ERSEC 28.2 — Security Behavior Assurance Research Direction

## Why the direction changed

ERSEC is not claiming novelty for authenticated scanning, stateful sequences,
authorization matrices, or workflow execution. Those primitives already exist
in adjacent tools. The research opportunity is the integration of reviewed
security properties, identity/resource relationships, evidence strength,
explicit uncertainty, and property-level longitudinal lineage.

## New mechanisms

### 1. Counterfactual Assurance Delta

Compare two runs at the property/case level. A previous violation becomes
`remediated_verified` only when the later run explicitly observes `pass`. A
missing or unavailable observation remains unverified.

### 2. Oracle Trust Lattice

Evidence strength is modeled independently from the verdict. The lattice can
rank low/medium/high evidence and operator-marked authoritative observations.
A trust score is not a probability and is never used to convert uncertainty to
pass.

### 3. Assurance Frontier

Surviving semantic mutants and uncovered policy dimensions become explicit
next-best assurance obligations. This changes the optimization target from
request volume to meaningful unverified security properties.

### 4. Assurance Events

ERSEC can emit a transport-neutral, OpenTelemetry-style event representation for
assurance deltas. Event names are stable while case IDs and transitions are
attributes, following the semantic-convention design principle that dynamic
values belong in attributes rather than event names.

## External research basis

OWASP identifies authorization as a major API security challenge and includes
broken object/property/function authorization in its 2023 API Top 10. NIST SSDF
emphasizes secure development practices across the SDLC. SLSA defines
provenance as verifiable information linking an artifact to how it was produced.
OpenTelemetry semantic conventions define structured events with stable names
and attributes for dynamic context. SARIF provides a standard interchange
format for analysis results.

These sources support engineering direction and interoperability, not claims of
ERSEC novelty.
