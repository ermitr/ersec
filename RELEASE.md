# ERSEC 29.1.1 Release Checklist

## Local validation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e .
ersec --version
ersec --self-test
python -m pytest -q
python -m py_compile ersec.py
rm -rf dist build *.egg-info
python -m build
python -m twine check dist/*
```

Then install the built wheel in a clean virtual environment and repeat `ersec --version` and `ersec --self-test`.

## Release identity

The public release version is **29.1.1**. Keep the following aligned:

- `pyproject.toml`
- ERSEC runtime version
- Debian package metadata
- man page
- tests/CI assertions
- changelog entry
- Git tag `v29.1.1`
- GitHub Release `v29.1.1`
- PyPI distribution `29.1.1`

Historical changelog entries retain their original versions; they are project history and must not be rewritten.

## GitHub

1. Push `main` and confirm the full CI matrix is green.
2. Confirm package validation and built-wheel installation tests are green.
3. Review `README.md`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, and workflows.
4. Create tag `v29.1.1`.
5. Create GitHub Release `v29.1.1`.

## PyPI

Configure Trusted Publishing for the existing `ersec` project:

- owner: `ermitr`
- repository: `ersec`
- workflow: `release.yml`
- environment: `pypi`

The release workflow builds and validates the exact distributions before the protected publish job uploads them.

## Assurance

- Run the Security Behavior Model validation.
- Generate the CycloneDX SBOM.
- Verify the built wheel in a clean environment.
- Confirm version consistency before tagging.

## 29.1.1

29.1.1 marks the first minor-version milestone for the Security Behavior Assurance
research direction. The release adds property-level lineage, an explicit oracle
trust lattice, conservative remediation deltas, and an assurance frontier.
These mechanisms are deterministic and do not replace operator-reviewed truth.
