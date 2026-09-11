from pathlib import Path
from ersec.ersec_assurance_fixtures import VERSION, build_fixture, load

ROOT = Path(__file__).resolve().parents[1]


def test_fixture_is_deterministic_and_29():
    spec = load(str(ROOT / "examples" / "disposable-multiprincipal-fixture-29.1.1.json"))
    a = build_fixture(spec); b = build_fixture(spec)
    assert VERSION == "29.1.1"
    assert a == b
    assert a["version"] == "29.1.1"
    assert len(a["oracle_truth"]) == 6
    assert a["safety"]["network_access"] is False


def test_fixture_rejects_secret_material():
    try:
        build_fixture({"identities": [{"id": "u", "token": "secret"}], "resources": [], "operations": []})
    except ValueError as exc:
        assert "credential" in str(exc)
    else:
        raise AssertionError("secret material was accepted")
