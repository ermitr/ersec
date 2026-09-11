# ERSEC 29.1.1 Deployment & Testing Guide

## 1. Requirements

- Python 3.9 or newer
- Linux, macOS, or Windows
- Network access only to systems you are authorized to test
- For the standard scanner: `requests`, `urllib3`, and `beautifulsoup4`
- Optional browser discovery requires Playwright

## 2. Install from the 29.1.1 wheel

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install ersec-29.1.1-py3-none-any.whl
ersec --version
```

Expected:

```text
ERSEC 29.1.1
```

## 3. Install from source

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
ersec --version
```

## 4. First safe test: offline assurance intelligence

This does not contact a target.

```bash
python ersec.py --assurance-intelligence examples/reality-29.1.1.example.json \
  --assurance-intelligence-declared examples/assurance-declaration.example.json \
  --assurance-intelligence-out /tmp/ersec-29.1.1-intelligence.json \
  --assurance-intelligence-budget 5
```

Inspect:

- `reality_gaps`
- `proof_debt`
- `next_best_observations`
- `security_impact_cone`

## 5. Build a Reality artifact

Given a previous ERSEC JSON scan report:

```bash
python ersec.py --reality-model scan.json --reality-out reality-29.1.1.json
```

## 6. Compile the release proof

```bash
python ersec.py --assurance-kernel reality-29.1.1.json \
  --assurance-kernel-out release-assurance-29.1.1.json
```

A result of `PASS` means every required proof obligation has positive evidence at the configured threshold. `BLOCKED` means evidence is insufficient. `FAIL` means a required obligation has explicit failing evidence.

## 7. Verify the proof chain

```bash
python ersec.py --verify-assurance-proof release-assurance-29.1.1.json
```

The command must report `valid: true` for an untampered artifact.

## 8. Compare two security realities

```bash
python ersec.py --reality-diff before.json after.json
```

and for Assurance Intelligence:

```bash
python ersec.py --assurance-intelligence-diff before.json after.json
```

Remember: a missing observation is not a security fix.

## 9. Run an authorized application scan

Start with the bounded baseline profile:

```bash
python ersec.py --target https://YOUR-AUTHORIZED-TARGET.example \
  --profile baseline \
  --max-requests 200 \
  --max-pages 50 \
  --output scan-29.1.1.json
```

For a larger authorized assessment, raise budgets deliberately rather than removing safety controls.

For authenticated authorization testing, use only credentials you are explicitly authorized to use:

```bash
python ersec.py --target https://YOUR-AUTHORIZED-TARGET.example \
  --bearer "$ERSEC_TOKEN" \
  --bearer-2 "$ERSEC_SECOND_TOKEN" \
  --profile deep \
  --output auth-scan-29.1.1.json
```

## 10. Test the release locally

From the repository root:

```bash
python -m py_compile *.py
pytest -q tests/test_assurance_intelligence.py
pytest -q tests/test_assurance_kernel.py
pytest -q tests/test_reality_fabric.py
pytest -q tests/test_assurance_lineage.py
pytest -q tests/test_assurance_mutation.py
pytest -q tests/test_benchmark_v6.py
pytest -q tests/test_benchmark_v7.py
pytest -q tests/test_research_benchmark.py
pytest -q tests/test_smoke.py
```

The test suite is intentionally split into bounded groups because several benchmark tests start controlled local fixtures and are slower when every test module is executed in one long-lived pytest process.

## 11. Test package integrity

```bash
python -m pip install --no-deps --target /tmp/ersec-29.1.1-clean ersec-29.1.1-py3-none-any.whl
PYTHONPATH=/tmp/ersec-29.1.1-clean python -c "import ersec, ersec_assurance_intelligence; print(ersec.ERSEC_VERSION, ersec_assurance_intelligence.VERSION)"
```

Expected:

```text
29.1.1 29.1.1
```

## 12. Debian deployment

```bash
sudo dpkg -i ersec_29.1.1-1_all.deb
sudo apt-get -f install
ersec --version
```

## 13. Recommended production workflow

```text
CI/build
  ↓
SBOM + provenance
  ↓
ERSEC 29.1.1 scan
  ↓
Security Reality Fabric
  ↓
Assurance Intelligence
  ↓
Assurance Kernel
  ↓
Proof-chain verification
  ↓
Release gate
```

ERSEC 29.1.1 does not claim that a green result proves absolute security. The platform intentionally preserves uncertainty and requires positive evidence for security claims.
