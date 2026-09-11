from ersec.ersec_identity_fabric import build, identity_id


def test_identity_id_is_stable_and_credential_free():
    a = identity_id({"name":"Admin", "role":"admin", "tenant":"A", "token":"SECRET"})
    b = identity_id({"name":"Admin", "role":"admin", "tenant":"A", "token":"OTHER"})
    assert a == b
    g = build({"identities":[{"name":"Admin","role":"admin","tenant":"A","token":"SECRET","evidence_refs":["e1"]}], "operations":[]})
    assert "token" not in str(g)


def test_application_resource_merge_and_auth_observation():
    ws={"identities":[],"applications":[],"operations":[
        {"id":"o1","method":"GET","url":"https://example.test/api/orders/1","path":"/api/orders/1","auth":[{"bearer":[]}],"evidence_refs":["e1"]},
        {"id":"o2","method":"POST","url":"https://example.test/api/orders/1","path":"/api/orders/1","auth":[{"bearer":[]}],"evidence_refs":["e2"]}],"assets":[]}
    g=build(ws)
    assert len(g["applications"]) == 1
    assert len(g["resources"]) == 1
    assert g["resources"][0]["methods"] == ["GET","POST"]
    assert g["resources"][0]["auth_observed"] is True
