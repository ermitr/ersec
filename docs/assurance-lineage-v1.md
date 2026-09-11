# ERSEC Security Assurance Lineage v1

ERSEC 29.1.0 introduces an offline assurance artifact that links a reviewed
security property to the selected scenario, observed evidence, verdict, and
(optional) source/build/deployment metadata. It also exposes an Oracle Trust
Lattice, an Assurance Frontier, and a conservative remediation delta.

The artifact is evidence bookkeeping, not formal proof. Trust scores describe
evidence strength; they are not probabilities of correctness. Missing or weak
observation never becomes PASS.

## CLI

```bash
ersec --assurance-lineage research-result.json
```

To compare two run artifacts:

```bash
ersec --assurance-delta before.json after.json
```

A prior violation is only marked `remediated_verified` when the later run
contains an explicit `pass` for the same case. Otherwise the transition remains
unverified/needs-review.
