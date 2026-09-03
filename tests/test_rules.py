from pathlib import Path

import pytest

from codesentinel.models import Language, Tier
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules

FIX = Path(__file__).parent / "fixtures"


def _scan(path: Path, lang=Language.PYTHON):
    return run_rules(parse(path.read_text(encoding="utf-8"), lang))


def test_vulnerable_fixture_findings():
    ids = {f.rule_id for f in _scan(FIX / "vulnerable" / "flask_app.py")}
    assert {"CS001", "CS002", "CS004", "CS005"} <= ids


def test_clean_fixture_has_no_deterministic_findings():
    findings = _scan(FIX / "clean" / "flask_app.py")
    deterministic = [f.rule_id for f in findings
                     if f.tier is Tier.DETERMINISTIC and f.rule_id != "CS006"]
    assert deterministic == []


def test_secrets_are_redacted():
    for f in _scan(FIX / "vulnerable" / "flask_app.py"):
        if f.rule_id == "CS001":
            assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet
            assert "*" in f.snippet


def test_every_finding_is_grounded():
    for f in _scan(FIX / "vulnerable" / "flask_app.py"):
        assert f.cwe.startswith("CWE-")
        assert f.owasp.startswith("A0")


def test_javascript_sql_injection():
    js = ("const q = `SELECT * FROM users WHERE id = ${req.params.id}`;\n"
          "db.query(q);\n"
          "app.get('/u/:id', (req,res) => "
          "db.query(`SELECT * FROM u WHERE id=${req.params.id}`));")
    ids = {f.rule_id for f in run_rules(parse(js, Language.JAVASCRIPT))}
    assert "CS002" in ids


def test_advisories_are_never_above_low():
    from codesentinel.models import Severity
    from codesentinel.rules.engine import ALL_RULES
    for rule in ALL_RULES:
        if rule.tier is Tier.ADVISORY:
            assert rule.severity <= Severity.LOW


def test_advisories_sort_below_deterministic():
    findings = _scan(FIX / "vulnerable" / "flask_app.py")
    tiers = [f.tier is Tier.ADVISORY for f in findings]
    assert tiers == sorted(tiers)


def test_extended_python_classes_fire():
    code = (
        "from flask import Flask, request, render_template_string\n"
        "import os\n"
        "app = Flask(__name__)\n"
        "@app.route('/p')\n"
        "def p():\n"
        "    return render_template_string('<b>' + request.args.get('n') + '</b>')\n"
        "@app.route('/f')\n"
        "def f():\n"
        "    return open(request.args.get('name')).read()\n"
        "app.run(debug=True)\n"
    )
    ids = {f.rule_id for f in run_rules(parse(code, Language.PYTHON))}
    assert {"CS007", "CS008", "CS009"} <= ids


def test_extended_js_classes_fire():
    js = (
        "const express = require('express');\n"
        "const fs = require('fs');\n"
        "const cors = require('cors');\n"
        "const app = express();\n"
        "app.use(cors({ origin: '*', credentials: true }));\n"
        "app.get('/f', (req, res) => { fs.readFile(req.query.name, (e,d) => "
        "res.send(d)); });\n"
        "app.post('/login', (req, res) => { db.query('SELECT 1'); });\n"
    )
    ids = {f.rule_id for f in run_rules(parse(js, Language.JAVASCRIPT))}
    assert "CS009" in ids
    assert "CS008" in ids
    assert "CS010" in ids or "CS011" in ids


def test_dependency_firewall_flags_a_slopsquat():
    code = "import reqeusts\nimport requests\n"
    findings = run_rules(parse(code, Language.PYTHON))
    cs006 = [f for f in findings if f.rule_id == "CS006"]
    assert cs006, "expected an unrecognised-dependency finding"
    assert "reqeusts" in cs006[0].explanation
    assert "requests" in cs006[0].explanation      # near-miss suggestion


def test_nested_expressions_are_not_reported_twice():
    """`app.get('/x', (req,res) => db.query(...))` is a call_expression inside a
    call_expression. Reporting the same flaw at two indentations is how a
    scanner teaches people to stop reading it."""
    js = ("const app = require('express')();\n"
          "app.get('/o/:id', (req, res) => {\n"
          "  db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);\n"
          "});\n")
    sql = [f for f in run_rules(parse(js, Language.JAVASCRIPT)) if f.rule_id == "CS002"]
    assert len(sql) == 1


# --------------------- CS006 precision: import name vs distribution name ------

COMMON_ALIASED_IMPORTS = [
    "yaml",       # pyyaml
    "cv2",        # opencv-python
    "PIL",        # pillow
    "sklearn",    # scikit-learn
    "bs4",        # beautifulsoup4
    "dateutil",   # python-dateutil
    "dotenv",     # python-dotenv
    "jwt",        # pyjwt
    "serial",     # pyserial
    "attr",       # attrs
    "docx",       # python-docx
    "fitz",       # pymupdf
    "OpenSSL",    # pyopenssl
    "Crypto",     # pycryptodome
    "psycopg2",   # psycopg2-binary
    "MySQLdb",    # mysqlclient
    "nacl",       # pynacl
]


@pytest.mark.parametrize("module", COMMON_ALIASED_IMPORTS)
def test_cs006_does_not_flag_a_common_aliased_import(module):
    """The manifest holds distribution names; the code writes import names.

    `import yaml` comes from the distribution `pyyaml`, and no hyphen or
    underscore rule bridges that. Before codesentinel/deps/aliases.py existed,
    every module in this list was reported as a possible slopsquat - including
    the most common non-stdlib import in Python.
    """
    findings = run_rules(parse(f"import {module}\n", Language.PYTHON))
    assert [f for f in findings if f.rule_id == "CS006"] == []


@pytest.mark.parametrize("module", ["reqeusts", "beautifulsoup", "pdfkit_lite"])
def test_cs006_still_catches_a_slopsquat(module):
    """The aliases must not have made the firewall permissive in general."""
    findings = run_rules(parse(f"import {module}\n", Language.PYTHON))
    assert [f for f in findings if f.rule_id == "CS006"], f"{module} went unflagged"


def test_alias_table_is_self_consistent():
    """Every distribution name in the table should be in the manifest, or the
    alias points at something the firewall still cannot resolve."""
    from codesentinel.deps.aliases import IMPORT_TO_DISTRIBUTION
    from codesentinel.deps.manifest import known_packages
    manifest = known_packages(Language.PYTHON)
    missing = sorted(
        f"{imp} -> {dist}"
        for imp, dists in IMPORT_TO_DISTRIBUTION.items()
        for dist in dists
        if dist.lower() not in manifest
    )
    assert missing == [], (
        "alias targets absent from the manifest (add them to the manifest, or "
        f"drop the alias): {missing}"
    )
