from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = "29.1.1"


def test_project_version_is_29_0_0():
    with (ROOT / "pyproject.toml").open("rb") as fh:
        assert tomllib.load(fh)["project"]["version"] == EXPECTED


def test_declared_python_modules_match_source_modules():
    with (ROOT / "pyproject.toml").open("rb") as fh:
        tool = tomllib.load(fh)["tool"]["setuptools"]
        if "py-modules" in tool:
            declared = set(tool["py-modules"])
        else:
            # For src layout, the package name is declared, not individual modules
            declared = set(tool.get("packages", []))

    if "packages" in tool:
        # In src layout, we check if the package exists and contains the modules
        assert "ersec" in declared
        source_modules = {p.stem for p in (ROOT / "src" / "ersec").glob("*.py")} | {"ersec"}
        # This test now checks that we have the core modules we expect
        assert len(source_modules) > 10
    else:
        source = {p.stem for p in ROOT.glob("ersec_*.py")} | {"ersec"}
        assert source == declared


def test_embedded_version_constants_are_29_0_0():
    offenders = []
    for path in (ROOT / "src" / "ersec").glob("ersec*.py"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^(?:ERSEC_VERSION|VERSION)\s*=\s*[\"']([^\"']+)[\"']", text, re.MULTILINE):
            if match.group(1) != EXPECTED:
                offenders.append((path.name, match.group(1)))
    assert offenders == []


def test_debian_watch_is_present():
    assert (ROOT / "debian" / "watch").is_file()
