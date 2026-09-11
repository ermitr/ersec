# ERSEC 29.1.0 on Kali Linux

## 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-yaml python3-requests python3-urllib3 python3-bs4
```

## 2. Install from this source tree

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Verify:

```bash
ersec --version
# ERSEC 29.1.0
```

## 3. Offline health check

```bash
ersec --self-test
```

The 29.1.0 built-in suite should complete with `Ran 66 tests` and `OK`.

## 4. Compile the reviewed security behavior policy

```bash
ersec --assurance-policy-compile \
  examples/security-behavior-policy-29.1.0.yaml \
  --assurance-policy-out assurance-plan-29.1.0.json
```

Validate it:

```bash
ersec --assurance-plan-validate assurance-plan-29.1.0.json
```

## 5. Normalize the application inventory

```bash
ersec --assurance-inventory \
  examples/api-behavior-inventory-29.1.0.json \
  --assurance-inventory-out inventory-29.1.0.json
```

## 6. Evaluate runtime-control evidence

```bash
ersec --assurance-controls \
  examples/runtime-control-evidence-29.1.0.json \
  --assurance-controls-out controls-29.1.0.json
```

`configured_only` is intentionally not treated as `observed_enforced`.

## 7. Run an authorized application assessment

Use only an application you own or are explicitly authorized to test:

```bash
ersec \
  --target https://YOUR-AUTHORIZED-STAGING-HOST \
  --profile baseline \
  --max-requests 200 \
  --max-pages 50 \
  --output scan-29.1.0.json \
  --sarif ersec-29.1.0.sarif \
  --junit ersec-29.1.0.xml
```

Then compile the Security Reality artifact:

```bash
ersec --reality-model scan-29.1.0.json --reality-out reality-29.1.0.json
```

Then Assurance Intelligence:

```bash
ersec --assurance-intelligence reality-29.1.0.json \
  --assurance-intelligence-out intelligence-29.1.0.json \
  --assurance-intelligence-budget 10
```

Then the proof-carrying release decision:

```bash
ersec --assurance-kernel reality-29.1.0.json \
  --assurance-kernel-out release-assurance-29.1.0.json
```

Verify the proof chain:

```bash
ersec --verify-assurance-proof release-assurance-29.1.0.json
```

## 8. Kali package installation

For a packaged install, install the 29.1.0 Debian package with:

```bash
sudo apt install ./ersec_29.1.0-1_all.deb
```

Then:

```bash
ersec --version
ersec --self-test
```

## Safety

ERSEC is designed for authorized, bounded, non-destructive security assessment. Keep credentials outside policy files and repositories. Do not enable state-changing or enforcement workflows against production unless the authorization, scope, rollback and cleanup requirements have been explicitly reviewed.

### Disposable multi-principal fixture planning

```bash
ersec --assurance-fixture examples/disposable-multiprincipal-fixture-29.1.0.json \
  --assurance-fixture-out fixture-29.1.0.json
```

This step is offline. It creates synthetic identity/resource truth for an authorized harness; it does not create accounts or contact the target.

## Concurrent assurance

Compile the bounded race-sensitive assurance plan locally:

```bash
python3 ersec.py --concurrent-assurance-compile examples/assurance-concurrency-29.1.0.json --concurrent-assurance-out concurrent-assurance-29.1.0.json
```

Evaluate evidence returned by an authorized harness:

```bash
python3 ersec.py --concurrent-assurance-evaluate concurrent-assurance-29.1.0.json evidence.json --concurrent-assurance-out concurrent-result-29.1.0.json
```

This planner does not itself issue concurrent requests.

## 10. 29.1.0 maturity/reproducibility validation

From the repository root:

```bash
python3 ersec.py --self-test
python3 ersec.py --roadmap-audit . --roadmap-audit-out roadmap-coverage-29.1.0.json
python3 ersec.py --build-assurance . --build-assurance-out build-assurance-29.1.0.json
python3 ersec.py --release-audit . --release-audit-out release-readiness-29.1.0.json
```

The build-assurance result must report `PASS` and `package_parity.status=MATCH`.

For Debian packaging in a full Debian/Kali packaging environment:

```bash
dpkg-buildpackage -us -uc -b
```

Then install the generated `ersec_29.1.0-1_all.deb` and run:

```bash
ersec --version
# ERSEC 29.1.0
ersec --self-test
```

For container validation, the repository contains a digest-pinned `Containerfile` and CI workflow. ERSEC itself never downloads a base image or invents a digest during offline assurance.

The roadmap is considered engineering-complete only when implementation evidence is present. External OWASP Benchmark Python, WAVSEP and Juice Shop scorecards must remain `not_executed` until a controlled run supplies raw output and ground-truth evidence.
