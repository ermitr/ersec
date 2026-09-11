# ERSEC 29.1.0 — Roadmap Coverage Audit

The roadmap audit maps the ten core Security Behavior Assurance features to source modules, tests, and evidence artifacts. It intentionally reports `PARTIAL` when explicit product or validation gaps remain; it never upgrades missing evidence to completion.

Run:

```bash
python ersec.py --roadmap-audit . --roadmap-audit-out roadmap-coverage-29.1.0.json
```

The report records:

- ten roadmap feature anchors;
- implementation and regression-test evidence;
- foundation/release-gate evidence;
- explicit remaining gaps;
- deterministic audit digest;
- safety and evidence principles.

Known 29.1.0 gaps include broader authoritative observer adapters, advanced producer/link learning, concurrent target-side assurance, independently proven container builds, cross-environment clean rebuild validation, and public external benchmark scorecards. These are deliberately surfaced instead of hidden behind a green dashboard.
