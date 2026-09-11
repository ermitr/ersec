# Security Behavior Graph v3

ERSEC models application security as relationships between identities, roles, tenants, resources, invariants, authorization decisions, and minimal counterexamples.

## Read-only verification

Graph v3 uses only explicitly modeled `GET`, `HEAD`, and `OPTIONS` operations. Missing credentials and out-of-scope resources remain `not_tested` rather than being interpreted as safe.

## Counterexample paths

When an invariant is violated, ERSEC emits a shortest explanatory path such as:

`identity:user_b -> role:user -> authorization-decision:user_b:order_a:GET -> resource:order_a -> tenant:tenant_a`

The path is evidence for review and regression control, not an exploitation recipe.

## Authorization matrix

The matrix contains one row for each modeled identity × resource × method combination, with expected status, observed status, verdict, and coverage. This makes cross-tenant and role-boundary review auditable.

## Stable graph identity

Graph fingerprints exclude volatile generation timestamps. Equivalent policy and evidence therefore produce comparable structural fingerprints across runs.
