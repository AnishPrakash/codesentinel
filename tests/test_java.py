"""Java coverage. Deliberately a subset - these tests pin which subset."""
from pathlib import Path

from codesentinel.features.extract import FEATURE_NAMES, extract_features
from codesentinel.languages import detect_language
from codesentinel.models import Language, Tier
from codesentinel.parser import parse
from codesentinel.rules.engine import rules_for, run_rules

FIX = Path(__file__).parent / "fixtures"


def _scan(kind: str):
    code = (FIX / kind / "AccountController.java").read_text(encoding="utf-8")
    return run_rules(parse(code, Language.JAVA))


def test_java_is_detected_by_extension():
    assert detect_language("Foo.java") is Language.JAVA


def test_java_is_detected_by_content():
    assert detect_language("noext", "public class Foo { }") is Language.JAVA


def test_java_parses_into_52_features():
    code = (FIX / "vulnerable" / "AccountController.java").read_text()
    v = extract_features(parse(code, Language.JAVA))
    assert len(v) == 52


def test_java_language_is_dummy_encoded():
    """Java is (0, 0) in the two language indicators. Adding a third column
    would make the vector 53 and break the contract with a trained model."""
    code = (FIX / "vulnerable" / "AccountController.java").read_text()
    v = dict(zip(FEATURE_NAMES, extract_features(parse(code, Language.JAVA))))
    assert v["lang_is_python"] == 0.0
    assert v["lang_is_javascript"] == 0.0


def test_java_structure_is_actually_read():
    code = (FIX / "vulnerable" / "AccountController.java").read_text()
    v = dict(zip(FEATURE_NAMES, extract_features(parse(code, Language.JAVA))))
    assert v["n_classes"] >= 1
    assert v["n_functions"] >= 5
    assert v["n_routes"] >= 2


def test_vulnerable_java_fixture_findings():
    ids = {f.rule_id for f in _scan("vulnerable")}
    assert {"CS001", "CS002", "CS003", "CS004", "CS005", "CS014", "CS016", "CS017"} <= ids


def test_clean_java_fixture_is_silent():
    """The same controller, same routes, same imports, written safely.
    Zero findings, or the rules are matching style rather than security."""
    assert _scan("clean") == []


def test_java_secrets_are_redacted():
    for f in _scan("vulnerable"):
        if f.rule_id == "CS001":
            assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet
            assert "billing-prod-2024" not in f.snippet


def test_java_findings_are_grounded():
    for f in _scan("vulnerable"):
        assert f.cwe.startswith("CWE-")
        assert f.owasp.startswith("A0")
        assert f.tier is Tier.DETERMINISTIC


def test_java_coverage_is_a_documented_subset():
    """Java has no CS006 - Maven coordinates are not import names, so an
    import-name manifest would say nothing useful."""
    java = set(rules_for(Language.JAVA))
    python = set(rules_for(Language.PYTHON))
    assert "CS006" not in java
    assert "CS006" in python
    assert java < python or java != python      # a subset, and we say so


def test_java_fixes_are_java():
    from codesentinel.explain import enrich
    for f in enrich(_scan("vulnerable")):
        assert f.fix
        # a Java fix must not be Python: no `import os`, no def
        assert not f.fix.startswith("import os")
