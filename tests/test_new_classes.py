"""CS014-CS017 and the shapes folded into existing classes.

These come from plan.md's pattern-feature table: unsafe deserialization,
disabled certificate validation, cleartext transport, secrets in logs, weak
ciphers, commented-out credentials, and mktemp.
"""
import pytest

from codesentinel.models import Language, Tier
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules


def ids(code: str, lang=Language.PYTHON) -> set[str]:
    return {f.rule_id for f in run_rules(parse(code, lang))}


# ------------------------------------------------- CS014 deserialization

@pytest.mark.parametrize("code", [
    "import pickle\ndef f(b):\n    return pickle.loads(b)\n",
    "import yaml\ndef f(b):\n    return yaml.load(b)\n",
    "import marshal\ndef f(b):\n    return marshal.loads(b)\n",
])
def test_cs014_python(code):
    assert "CS014" in ids(code)


@pytest.mark.parametrize("code", [
    "import yaml\ndef f(b):\n    return yaml.load(b, Loader=yaml.SafeLoader)\n",
    "import yaml\ndef f(b):\n    return yaml.safe_load(b)\n",
    "import json\ndef f(b):\n    return json.loads(b)\n",
])
def test_cs014_python_safe_forms_are_silent(code):
    assert "CS014" not in ids(code)


def test_cs014_javascript():
    js = "const s = require('node-serialize');\nfunction f(r){return s.unserialize(r);}"
    assert "CS014" in ids(js, Language.JAVASCRIPT)


# ------------------------------------------ CS015 certificate validation

@pytest.mark.parametrize("code", [
    "import requests\ndef f(u):\n    return requests.get(u, verify=False)\n",
    "import ssl\nctx = ssl._create_unverified_context()\n",
])
def test_cs015_python(code):
    assert "CS015" in ids(code)


def test_cs015_python_default_is_silent():
    assert "CS015" not in ids("import requests\ndef f(u):\n    return requests.get(u)\n")


def test_cs015_javascript():
    js = "const agent = { rejectUnauthorized: false };"
    assert "CS015" in ids(js, Language.JAVASCRIPT)


# ------------------------------------------- CS016 cleartext transmission

def test_cs016_fires_on_a_request_target():
    assert "CS016" in ids('API_URL = "http://api.example.com/v1"\n')


def test_cs016_ignores_localhost():
    assert "CS016" not in ids('API_URL = "http://localhost:8000"\n')


def test_cs016_ignores_a_namespace_url():
    code = 'NS = "http://www.w3.org/2001/XMLSchema-instance"\n'
    assert "CS016" not in ids(code)


def test_cs016_ignores_a_plain_string():
    """No name hint and no request call - we cannot tell it is a request."""
    assert "CS016" not in ids('MESSAGE = "see http://example.com/docs for details"\n')


def test_cs016_survives_the_word_boundary_trap():
    """REPORT_ENDPOINT has word characters either side of 'endpoint', so a
    \\b-anchored pattern would never match it. This test exists because that
    bug shipped once already."""
    assert "CS016" in ids('REPORT_ENDPOINT = "http://reports.internal.example/v1"\n')


# ----------------------------------------------- CS017 secrets in logs

def test_cs017_python():
    code = ("import logging\nlog = logging.getLogger(__name__)\n"
            "def f(password):\n    log.info('pw=%s', password)\n")
    assert "CS017" in ids(code)


def test_cs017_ignores_a_redacted_value():
    code = ("import logging\nlog = logging.getLogger(__name__)\n"
            "def f(password):\n    log.info('pw=%s', mask(password))\n")
    assert "CS017" not in ids(code)


def test_cs017_ignores_an_ordinary_log_line():
    code = ("import logging\nlog = logging.getLogger(__name__)\n"
            "def f(user_id):\n    log.info('login for %s', user_id)\n")
    assert "CS017" not in ids(code)


def test_cs017_redacts_what_it_reports():
    code = 'def f():\n    print("token=abcdef1234567890")\n'
    for f in run_rules(parse(code, Language.PYTHON)):
        if f.rule_id == "CS017":
            assert "abcdef1234567890" not in f.snippet


def test_cs017_javascript():
    js = "function f(apiKey) { console.log('key', apiKey); }"
    assert "CS017" in ids(js, Language.JAVASCRIPT)


# --------------------------- shapes folded into classes that already existed

def test_cs001_catches_a_commented_out_credential():
    """Commenting a credential out removes it from execution, not from the file."""
    code = '# DB_PASSWORD = "old-production-password"\nx = 1\n'
    assert "CS001" in ids(code)


def test_cs001_catches_a_google_api_key():
    """The key is assembled at runtime, never written as one literal.

    A 39-character AIza... string sitting in a source file is what Google's
    format looks like, so GitHub's secret scanner flags it on push - correctly,
    since it cannot know ours is invented. Building it from parts keeps the
    test honest and keeps the repository quiet. Do not "tidy" this back into a
    single string: it opened a secret-scanning alert once already."""
    fake = "AIza" + "SyD-" + "0123456789" + "abcdefghij" + "klmnopqrstu"
    assert len(fake) == 39
    assert "CS001" in ids(f'KEY = "{fake}"\n')


def test_cs004_catches_a_weak_cipher():
    code = ("from Crypto.Cipher import DES\n"
            "def f(k):\n    return DES.new(k, DES.MODE_ECB)\n")
    assert "CS004" in ids(code)


def test_cs013_catches_mktemp():
    code = "import tempfile\ndef f():\n    return tempfile.mktemp()\n"
    found = [f for f in run_rules(parse(code, Language.PYTHON)) if f.rule_id == "CS013"]
    assert found
    assert found[0].tier is Tier.ADVISORY


# ----------------------------------------------------- taxonomy invariants

def test_every_covered_class_has_a_template_and_grounding():
    from codesentinel.explain.templates import TEMPLATES, cwe_data, owasp_data
    from codesentinel.rules.engine import COVERED
    for rid, _name, cwe, owasp, _tier in COVERED:
        assert rid in TEMPLATES, f"{rid} has no template"
        assert cwe in cwe_data(), f"{cwe} missing from cwe.json"
        assert owasp in owasp_data(), f"{owasp} missing from owasp.json"


def test_every_deterministic_class_can_be_learned():
    """progress() counts mastery out of the deterministic classes, so every one
    of them must have a question and a rubric or the denominator is a lie."""
    from codesentinel.explain.socratic import QUESTIONS, RUBRIC
    from codesentinel.rules.engine import DETERMINISTIC
    for rid, *_ in DETERMINISTIC:
        assert rid in QUESTIONS, f"{rid} has no comprehension question"
        assert rid in RUBRIC, f"{rid} has no rubric"


def test_model_class_order_matches_the_deterministic_set():
    from codesentinel.rules.engine import DETERMINISTIC
    from codesentinel.triage.model import CLASS_ORDER
    assert set(CLASS_ORDER) == {c[0] for c in DETERMINISTIC}


def test_nist_covers_every_class():
    from codesentinel.explain.templates import nist_data
    from codesentinel.rules.engine import COVERED
    data = nist_data()
    for rid, *_ in COVERED:
        assert rid in data, f"{rid} has no NIST control mapping"
        assert data[rid]["control"]


def test_nist_is_off_by_default_and_on_with_the_flag():
    from codesentinel.explain import templates
    from codesentinel.models import Finding, Severity
    f = Finding(rule_id="CS002", title="t", severity=Severity.CRITICAL, cwe="CWE-89",
                owasp="A03:2021 - Injection", line=1, end_line=1, column=0,
                snippet="", language=Language.PYTHON)
    assert "NIST" not in templates.grounding_block(f)
    assert "NIST SP 800-53" in templates.grounding_block(f, include_nist=True)


# --------------- precision guards found by scanning our own source ------------
# Each of these fired on CodeSentinel itself before the rule was narrowed.

def test_cs016_ignores_prose_that_mentions_a_url():
    """Our own explanation template says 'http:// is unencrypted'. That is
    documentation, not a request target."""
    code = 'WHY = "http:// is unencrypted. Everything in the request, the URL, the body."'
    assert "CS016" not in ids(code)


def test_cs017_ignores_a_message_that_merely_says_password():
    """A prompt is not a leak. Only an identifier being logged is."""
    code = 'def f():\n    print("enter your password below")\n'
    assert "CS017" not in ids(code)


def test_cs017_still_catches_an_fstring_interpolation():
    code = ("import logging\nlog = logging.getLogger(__name__)\n"
            "def f(api_key):\n    log.info(f'calling with {api_key}')\n")
    assert "CS017" in ids(code)


def test_codesentinel_is_clean_on_its_own_source():
    """Dogfooding as a test. If a rule starts firing on our own code it is
    almost always the rule that is wrong, and this catches it in CI."""
    from pathlib import Path

    from codesentinel.languages import detect_language
    pkg = Path(__file__).resolve().parent.parent / "codesentinel"
    offenders = []
    for path in sorted(pkg.rglob("*.py")):
        code = path.read_text(encoding="utf-8")
        lang = detect_language(path.name, code)
        for f in run_rules(parse(code, lang), local_root=path.parent):
            offenders.append(f"{path.name}:{f.line} {f.rule_id} {f.title}")
    assert offenders == [], "scanner fires on its own source:\n" + "\n".join(offenders)
