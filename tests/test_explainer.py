from pathlib import Path

from codesentinel.explain import enrich
from codesentinel.explain.grader import grade
from codesentinel.models import Language, Severity, Tier
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules

FIX = Path(__file__).parent / "fixtures"


def _findings():
    code = (FIX / "vulnerable" / "flask_app.py").read_text()
    return enrich(run_rules(parse(code, Language.PYTHON)))


def test_every_finding_has_all_four_parts():
    for f in _findings():
        assert f.explanation and f.attack and f.fix
        assert f.cwe in f.explanation           # grounding is quoted, not implied


def test_owasp_is_quoted_too():
    for f in _findings():
        key = f.owasp.split(" ")[0]
        assert key in f.explanation


def test_critical_deterministic_findings_are_gated():
    for f in _findings():
        if f.severity >= Severity.CRITICAL and f.tier is Tier.DETERMINISTIC:
            assert f.question, f"{f.rule_id} has no comprehension question"


def test_advisories_are_never_gated():
    for f in _findings():
        if f.tier is Tier.ADVISORY:
            assert f.question == ""


def test_grader_accepts_a_correct_answer():
    ok, msg, _ = grade("CS005", (
        "It returns the other user's record, because the query looks up the row by the "
        "id from the URL and never checks ownership against the logged in user."
    ))
    assert ok, msg


def test_grader_rejects_a_guess():
    ok, _, _ = grade("CS005", "it is insecure and bad")
    assert not ok


def test_grader_rejects_parroting_the_question():
    ok, _, _ = grade("CS002", "the database receives the value 1 OR 1=1")
    assert not ok      # names the input, never explains the effect


def test_every_rule_class_has_a_template():
    from codesentinel.explain.templates import TEMPLATES
    from codesentinel.rules.engine import COVERED
    for rid, *_ in COVERED:
        assert rid in TEMPLATES, f"{rid} has no explanation template"
        assert TEMPLATES[rid]["fix_python"] and TEMPLATES[rid]["fix_javascript"]
