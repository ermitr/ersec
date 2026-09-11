# ERSEC 29.1.0 — Runtime Architecture and Performance Split

ERSEC 29.1.0 keeps the existing public `ersec` import surface while splitting the runtime entry point into three layers:

- `ersec.py` — tiny compatibility facade with lazy public-symbol loading and a zero-dependency version fast path.
- `ersec_cli.py` — command-line bootstrap; it handles cheap CLI paths before loading the assessment engine.
- `ersec_core.py` — the existing assessment engine and security functionality, preserved behind the stable facade.

This is an incremental architectural split, not a compatibility-breaking rewrite. Existing code such as `from ersec import ScanConfig` continues to work; the facade loads `ersec_core` only when that symbol is actually requested.

## Performance goals

The split reduces cold startup cost for version checks and prevents the CLI compatibility layer from eagerly importing every assurance, benchmark, reporting, and integration module. Future command-level modules can be extracted behind the same boundary without changing the public CLI contract.

ERSEC should measure startup and scan throughput before and after optimization. Security semantics, scope enforcement, evidence integrity, and deterministic assurance behavior must not be weakened for performance.

## Frontend

The offline HTML dashboard was upgraded for 29.1.0 with a denser security-operations cockpit layout, improved typography using local/system font stacks, KPI telemetry, responsive layouts, clearer hierarchy, keyboard-friendly controls, reduced-motion support, and no external font/CDN dependency.

## Bounded execution fabric

`ersec_scheduler.py` owns bounded execution of independent detector jobs. It returns indexed outcomes so concurrent execution does not make reports order-dependent. The scheduler can cooperatively cancel queued work when the shared request budget is exhausted. Network policy remains in `SafeHttpClient`; the scheduler cannot expand scope or bypass authorization.


### Differential Identity Matrix (29.1.0)

The Security Boundary Lab now exposes an offline `compile_differential_matrix()` API. It constructs deterministic, credential-free obligations across modeled identities when they differ by tenant or role. Only safe read methods (`GET`, `HEAD`, `OPTIONS`) are emitted by the matrix compiler. Each case records the compared identities, tenant/role context, resource, expected denial statuses, forbidden fields, and an explicit non-network/non-destructive safety contract. Missing observations remain inconclusive rather than passing.
