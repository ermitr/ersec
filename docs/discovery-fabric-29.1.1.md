# ERSEC 29.1.1 — Discovery Fabric

The Discovery Fabric is the canonical normalization layer between imported reconnaissance/application evidence and ERSEC's security-behavior graph.

## Design

- **Passive by default:** importing evidence never contacts a target.
- **Deterministic IDs:** identities are derived from normalized semantic facts rather than import time.
- **Evidence-linked:** every normalized node/edge retains references to the source evidence records.
- **Conservative merging:** query values do not create separate operation identities; host, method, path, and query-parameter names define the canonical operation.
- **Stable output:** nodes and edges are sorted deterministically for reproducible exports.

## Current node types

`asset`, `service`, `operation`, `identity`, and `finding`.

## Current relationships

- asset → service (`hosts_service`)
- asset → operation (`exposes_operation`)
- service → operation (`serves_operation`)
- finding → asset (`affects_asset`)
- identity → operation (`identity_can_reach`) when explicit operation references are supplied

The fabric intentionally does not infer compromise, exploitability, or authorization success merely from graph connectivity.

## Workspace export

`ersec --workspace-export` now emits a `discovery_fabric` object alongside the original evidence-oriented workspace records. This creates a clean hand-off point for the next roadmap stages: identity-aware authorization, safe business-flow analysis, attack-path reasoning, and proof generation.
