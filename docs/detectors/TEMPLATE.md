# Detector Specification: [DETECTOR_NAME]

## 1. Detection Logic
**Core Hypothesis**: Describe exactly what the detector is looking for and why it indicates a vulnerability.
**Oracle Strategy**: Explain the logic used to decide between `PASS`, `VIOLATION`, and `INCONCLUSIVE`.

## 2. Evidence Requirements
**Minimum Evidence**: What is the absolute minimum request/response data needed to prove this finding?
**Redaction Rules**: Which fields in the evidence must be redacted for privacy?

## 3. Confidence & Uncertainty
**Confidence High**: Describe the conditions where the detector is nearly 100% certain.
**Confidence Low**: Describe cases where the detector might produce a false positive.
**Inconclusive State**: When should the detector return `INCONCLUSIVE` instead of a verdict?

## 4. Fixtures (The Quality Gate)
- [ ] **Positive Fixture**: (Link to fixture/case) - A case that must be flagged.
- [ ] **Negative Fixture**: (Link to fixture/case) - A case that must NOT be flagged.
- [ ] **Regression Test**: (Link to test) - A case that was previously a bug and is now fixed.

## 5. Limitations
- **False Positive Risk**: Describe known scenarios where this detector fails.
- **False Negative Risk**: Describe scenarios this detector cannot detect.

## 6. Remediation
**Fix Description**: How should an engineer fix this specific vulnerability?
**Verification**: How can the engineer use ERSEC to prove the fix works?

---
**Review Status**:
- [ ] Specification Reviewed by Maintainer
- [ ] Benchmark Results Verified
- [ ] Evidence Reproducibility Confirmed
