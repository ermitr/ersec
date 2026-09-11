from ersec_provenance import build


def evidence():
    return {"certificate_digest":"abc","release_id":"29.1.0","commit":"deadbeef","artifact_refs":[{"artifact":"ersec","digest":"123"}]}


def test_provenance_digest_reproducible_with_explicit_environment():
    a = build(evidence(), environment={"os":"linux","python":"3.11"})
    b = build(evidence(), environment={"python":"3.11","os":"linux"})
    assert a["statement_digest"] == b["statement_digest"]


def test_provenance_environment_is_explicit():
    a = build(evidence(), environment={"builder_platform":"ci-linux"})
    assert a["statement"]["predicate"]["metadata"]["builder_platform"] == "ci-linux"
    assert "platform" not in a["statement"]["predicate"]["metadata"]
