from ersec_attack_graph import build, paths

def test_graph_is_provenance_aware_and_deterministic():
    ws={"assets":[{"host":"example.test"}],"services":[],"operations":[],"identities":[],"findings":[{"id":"F1","rule_id":"BOLA","host":"example.test","severity":"high","source_evidence":"E1"}],"evidence":[{"id":"E1","kind":"nuclei"}]}
    a=build(ws); b=build(ws)
    assert a["digest"]==b["digest"]
    assert a["governance"]["compromise_claim"] is False
    assert all(e["evidence_refs"] is not None for e in a["edges"])

def test_graph_links_operation_to_finding():
    ws={"assets":[{"host":"example.test"}],"services":[],"operations":[{"method":"GET","host":"example.test","path":"/api/x","query_parameter_names":[],"evidence_refs":["E1"]}],"findings":[{"id":"F1","rule_id":"R","host":"example.test","matched_at":"https://example.test/api/x","severity":"high","source_evidence":"E2"}],"evidence":[]}
    g=build(ws); assert any(e["relation"]=="may_indicate" for e in g["edges"])

def test_paths_are_evidence_paths_not_compromise_claims():
    ws={"assets":[{"host":"example.test"}],"services":[{"host":"example.test","port":443,"scheme":"https","evidence_refs":["E1"],"confidence":"high"}],"operations":[{"method":"GET","host":"example.test","path":"/api/x","query_parameter_names":[],"evidence_refs":["E1"]}],"findings":[{"id":"F1","rule_id":"R","host":"example.test","severity":"high","source_evidence":"E2"}],"evidence":[]}
    g=build(ws); assert isinstance(paths(g),list)

def test_graph_normalizes_asset_host_keys_for_edges():
    ws={"assets":[{"host":"Example.TEST."}],"services":[{"host":"example.test","port":443,"scheme":"https","evidence_refs":["E1"]}],"operations":[],"findings":[],"evidence":[]}
    g=build(ws)
    asset_ids={n["id"] for n in g["nodes"] if n["kind"] == "asset"}
    assert len(asset_ids) == 1
    assert all(e["source"] in asset_ids for e in g["edges"])
