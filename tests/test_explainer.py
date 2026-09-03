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


# ------------- one rule id, two different problems: CS004 variants ------------

def _cs004(code, lang=Language.PYTHON):
    from codesentinel.rules.engine import run_rules as _rr
    for f in enrich(_rr(parse(code, lang))):
        if f.rule_id == "CS004":
            return f
    raise AssertionError("CS004 did not fire")


def test_cs004_random_gets_the_randomness_explanation_not_the_hash_one():
    """The tool flagged `new Random()` and then explained MD5 collisions.

    A broken hash and a predictable RNG are both "unsuitable cryptography" and
    share a CWE, but the reason, the attack and the fix have nothing in common.
    An explanation that contradicts its own finding costs more credibility than
    the finding earns.
    """
    f = _cs004('public class A { public String t(){ Random r = new Random();'
               ' return "password" + r.nextLong(); } }', Language.JAVA)
    assert "MD5" not in f.explanation
    assert "collision" not in f.explanation.lower()
    assert "seed" in f.explanation.lower() or "guess" in f.explanation.lower()
    assert "SecureRandom" in f.fix
    assert "MessageDigest" not in f.fix


def test_cs004_hash_still_gets_the_hash_explanation():
    f = _cs004('import hashlib\ndef h(d):\n    return hashlib.md5(d)\n')
    assert "MD5" in f.explanation
    assert "sha256" in f.fix.lower()


def test_cs004_python_random_gets_secrets_not_argon2():
    f = _cs004("import random\ndef t():\n"
               "    password_seed = random.randint(0, 9)\n    return password_seed\n")
    assert "secrets" in f.fix
    assert "PasswordHasher" not in f.fix


def test_every_variant_pattern_matches_something_real():
    """A variant whose pattern never fires is dead configuration that looks
    like coverage."""
    import re as _re
    from codesentinel.explain.templates import TEMPLATES, VARIANTS
    for rule_id, variants in VARIANTS.items():
        assert rule_id in TEMPLATES, f"{rule_id} has a variant but no base template"
        for pattern, override in variants:
            assert isinstance(pattern, _re.Pattern)
            assert override, f"{rule_id} has an empty variant"
            assert set(override) <= set(TEMPLATES[rule_id]) | {"fix_java"}, (
                f"{rule_id} variant introduces a key the base template lacks")
