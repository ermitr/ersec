from ersec_discovery import build, node_id


def test_fabric_is_deterministic_and_merges_duplicate_observations():
    ws = {
        "assets": [{"host": "Example.test", "confidence": "medium", "evidence_refs": ["e1"]}],
        "services": [{"host": "example.test", "port": 443, "scheme": "https", "evidence_refs": ["e1"]}],
        "operations": [
            {"method": "GET", "url": "https://example.test/api/x?b=2&a=1", "query_parameter_names": ["b", "a"], "evidence_refs": ["e2"]},
            {"method": "GET", "url": "https://example.test/api/x?a=3&b=4", "query_parameter_names": ["a", "b"], "evidence_refs": ["e3"]},
        ],
        "findings": [], "identities": [],
    }
    a = build(ws); b = build(ws)
    assert a == b
    assert a["statistics"]["by_kind"]["operation"] == 1
    op = next(n for n in a["nodes"] if n["kind"] == "operation")
    assert op["evidence_refs"] == ["e2", "e3"]
    assert any(e["kind"] == "serves_operation" for e in a["edges"])


def test_finding_links_only_to_known_asset():
    ws = {"assets": [{"host": "example.test", "evidence_refs": ["e1"]}], "services": [], "operations": [],
          "identities": [], "findings": [{"id": "f1", "host": "example.test", "rule_id": "R1", "source_evidence": "e2"}]}
    g = build(ws)
    assert {e["kind"] for e in g["edges"]} == {"affects_asset"}
    assert node_id("asset", {"host": "example.test"}) in {e["target"] for e in g["edges"]}
