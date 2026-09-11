# ERSEC 29.1.1 — Phase 1 Safe Execution Boundaries

Phase 1 establishes conservative network and execution defaults for authorized,
bounded security assessment.

## Read-only by default

The default HTTP method set is:

- `GET`
- `HEAD`
- `OPTIONS`

State-changing methods require all of the following:

1. the method is explicitly present in the effective scope;
2. `--allow-state-changing-methods` is explicitly supplied;
3. an authorization manifest is supplied and permits the method, host, port,
   path, and testing window.

A missing or ambiguous authorization boundary fails closed.

## Network destination policy

Before network I/O, ERSEC validates the target host, port, method, and scope.
DNS names are resolved for every network operation rather than relying on a
long-lived DNS cache. Every returned address must satisfy the same destination
policy.

By default ERSEC blocks loopback, private, link-local, multicast, reserved,
unspecified, and IPv4-mapped-private destinations. Controlled local testing can
explicitly opt in with `--allow-private-addresses`.

This policy is applied to IPv4 and IPv6 results and fails closed on DNS
resolution errors.

## Redirects

Automatic `requests` redirects are disabled. Callers that intentionally follow
redirects must use ERSEC's per-hop redirect path. Each destination is
re-authorized against the current scope before another request is issued, and
the redirect count is bounded by `ScopeConfig.max_redirects` (default 5).

## Dry-run and scope preview

`--scope-preview` and `--dry-run` are offline planning operations. They do not
perform DNS resolution or HTTP requests. They expose the effective hosts,
ports, paths, methods, private-address policy, request budget, redirect limit,
and state-changing authorization status.

State-changing previews are descriptive only; a preview never implies that a
state-changing request will be executed.

## Audit telemetry

`SafeHttpClient.audit_events` records privacy-minimized boundary decisions with
schema `ersec-network-audit/1`. URLs are passed through ERSEC sensitive-URL
redaction, request bodies and credential values are not stored, and each event
contains the configured test reason.

## TLS

TLS certificate verification remains enabled by default. Disabling verification
requires the visible `--insecure` opt-in.

## Evidence semantics

A blocked request is not a clean result. Missing, blocked, or unavailable
observations remain explicit and must not be promoted to `pass` merely because
no vulnerability was observed.

Phase 1 is a safety boundary, not evidence that an arbitrary target is secure
and not a claim of resistance to every possible network-layer race. External
security review remains necessary for high-assurance deployments.
