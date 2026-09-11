# ERSEC quality checks

ERSEC CI runs Ruff and Bandit as an advisory baseline while the project transitions from the historical monolithic implementation to a modular core. These checks must not be mistaken for a clean static-analysis result until the complete codebase passes them.

The blocking CI gates remain compilation, ERSEC self-tests, pytest, package builds, distribution validation, and installed-wheel checks. Static-analysis failures are intentionally visible but non-blocking in this transition release.


## Stable artifact contract

Every completed or incomplete scan serializes the stable `ersec-scan-report/1`
contract. Consumers can run `ersec --validate-report REPORT.json` to catch malformed
output before using it as CI or governance evidence. Validation checks structure and
completeness metadata; it is not a security proof.

Security Behavior Assurance Coverage uses:

`tested model cells / applicable model cells`

Untested, out-of-scope, and inconclusive cells remain visible and are never counted as secure.
