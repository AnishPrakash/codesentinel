from pathlib import Path

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
