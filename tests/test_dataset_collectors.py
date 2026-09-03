"""Collector parsing, against fixtures shaped like the real sources.

Two of these collectors could not be run against their real archives while they
were written: samate.nist.gov (Juliet) and zenodo.org (CVEfixes) were both
unreachable. Shipping an untested parser and calling it done is how the Java
dependency shipped without being declared, so the parsing logic is pinned here
against fixtures built to each source's documented shape.

This is not the same as having run it on the real data. It catches a broken
regex or a wrong column name; it cannot catch a schema that has moved. Both
collectors print what they skipped and both have a --limit flag for exactly
that reason - run them small first.
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codesentinel.triage.labels import (          # noqa: E402
    CWE_TO_CLASS, class_for_cwe, label_vector, normalise_cwe,
)
from codesentinel.triage.model import CLASS_ORDER  # noqa: E402


# ------------------------------------------------------------ label contract

@pytest.mark.parametrize("raw,expected", [
    (89, "CWE-89"), ("89", "CWE-89"), ("CWE-89", "CWE-89"),
    ("cwe_89", "CWE-89"), (" CWE-89 ", "CWE-89"), ("", ""),
])
def test_normalise_cwe(raw, expected):
    assert normalise_cwe(raw) == expected


def test_class_for_cwe_covers_the_owasp_benchmark_cwes():
    """The CWEs OWASP Benchmark actually ships. If a mapping is dropped, that
    whole category silently stops contributing training signal."""
    for cwe, cls in [("22", "CS008"), ("78", "CS003"), ("79", "CS007"),
                     ("89", "CS002"), ("327", "CS004"), ("328", "CS004"),
                     ("330", "CS004")]:
        assert class_for_cwe(cwe) == cls, f"CWE-{cwe} no longer maps to {cls}"


def test_unmapped_cwe_returns_none_rather_than_guessing():
    # LDAP and XPath injection are real, and we do not cover them. Forcing them
    # into CS002 would teach the model that SQL injection looks like XPath.
    assert class_for_cwe("90") is None
    assert class_for_cwe("643") is None


def test_label_vector_is_multi_hot_in_model_order():
    v = label_vector(["CWE-89", "CWE-798"], CLASS_ORDER)
    assert len(v) == len(CLASS_ORDER)
    assert v[CLASS_ORDER.index("CS002")] == 1
    assert v[CLASS_ORDER.index("CS001")] == 1
    assert sum(v) == 2


def test_every_deterministic_class_has_at_least_one_cwe():
    for cls in CLASS_ORDER:
        assert any(v == cls for v in CWE_TO_CLASS.values()), (
            f"{cls} has no CWE mapped to it, so nothing can ever train it")


# ------------------------------------------------------------------- Juliet

JULIET_FIXTURE = '''\
/* Juliet-shaped test case. */
package testcases.CWE89_SQL_Injection;

import java.sql.*;

public class CWE89_SQL_Injection__connect_tcp_execute_01 {
    public void bad() throws Throwable {
        String data = readFromSocket();
        String query = "SELECT * FROM users WHERE name='" + data + "'";
        Statement st = conn.createStatement();
        st.executeQuery(query);
    }

    public void goodG2B() throws Throwable {
        String data = "safeLiteral";
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE name=?");
        ps.setString(1, data);
        ps.executeQuery();
    }

    public void goodB2G() throws Throwable {
        String data = readFromSocket();
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE name=?");
        ps.setString(1, data);
        ps.executeQuery();
    }
}
'''


def test_juliet_collector_splits_bad_from_good(tmp_path):
    from scripts.dataset.collect_juliet import collect

    src = tmp_path / "CWE89_SQL_Injection__connect_tcp_execute_01.java"
    src.write_text(JULIET_FIXTURE, encoding="utf-8")

    records = collect(tmp_path)
    assert len(records) == 3, [r.path for r in records]

    bad = [r for r in records if r.is_vulnerable]
    good = [r for r in records if not r.is_vulnerable]
    assert len(bad) == 1 and len(good) == 2

    assert bad[0].cwes == ["CWE-89"]
    assert "executeQuery(query)" in bad[0].code
    # The safe twin carries no CWE - labelling it would invert its meaning.
    assert good[0].cwes == []
    assert all("prepareStatement" in r.code for r in good)


def test_juliet_methods_are_wrapped_so_they_parse(tmp_path):
    """A bare method is not a compilation unit. If the wrapper is dropped the
    feature extractor sees an error node and every structural feature is zero."""
    from codesentinel.features.extract import FEATURE_NAMES, extract_features
    from codesentinel.models import Language
    from codesentinel.parser import parse
    from scripts.dataset.collect_juliet import collect

    (tmp_path / "CWE89_x.java").write_text(JULIET_FIXTURE, encoding="utf-8")
    rec = collect(tmp_path)[0]

    v = dict(zip(FEATURE_NAMES, extract_features(parse(rec.code, Language.JAVA))))
    assert v["n_functions"] >= 1
    assert v["n_classes"] >= 1


def test_juliet_skips_a_file_with_no_cwe_in_its_name(tmp_path):
    from scripts.dataset.collect_juliet import collect
    (tmp_path / "CWE_Helper.java").write_text(JULIET_FIXTURE, encoding="utf-8")
    assert collect(tmp_path) == []


# ----------------------------------------------------------------- CVEfixes

def _cvefixes_fixture(db: Path) -> None:
    """A database with CVEfixes' documented shape and two rows."""
    conn = sqlite3.connect(db)
    conn.executescript("""
        create table method_change (
            method_change_id text, file_change_id text, name text,
            code text, before_change text);
        create table file_change (
            file_change_id text, hash text, filename text, repo_url text);
        create table commits (hash text);
        create table fixes (hash text, cve_id text);
        create table cwe_classification (cve_id text, cwe_id text);
    """)
    conn.execute("insert into method_change values (?,?,?,?,?)", (
        "m1", "f1", "get_user",
        "def get_user(uid):\n    return db.execute('SELECT * FROM u WHERE id = ?', (uid,))\n",
        "def get_user(uid):\n    return db.execute('SELECT * FROM u WHERE id = ' + uid)\n",
    ))
    conn.execute("insert into file_change values (?,?,?,?)",
                 ("f1", "h1", "app/views.py", "https://github.com/acme/webapp"))
    conn.execute("insert into commits values ('h1')")
    conn.execute("insert into fixes values ('h1', 'CVE-2021-0001')")
    conn.execute("insert into cwe_classification values ('CVE-2021-0001', 'CWE-89')")
    conn.commit()
    conn.close()


def test_cvefixes_collector_yields_a_patch_pair(tmp_path):
    from scripts.dataset.collect_cvefixes import collect

    db = tmp_path / "CVEfixes.db"
    _cvefixes_fixture(db)
    records = collect(db, limit=None)

    assert len(records) == 2, [r.path for r in records]
    before = [r for r in records if r.is_vulnerable][0]
    after = [r for r in records if not r.is_vulnerable][0]

    assert "+ uid" in before.code            # the vulnerable version
    assert "?" in after.code                 # the parameterised fix
    assert before.cwes == ["CWE-89"]
    assert after.cwes == []
    # Both halves of a pair must share a group, or the split can separate them.
    assert before.group == after.group == "cvefixes:acme/webapp"
    assert before.language == "python"


def test_cvefixes_skips_languages_we_cannot_parse(tmp_path):
    from scripts.dataset.collect_cvefixes import collect

    db = tmp_path / "CVEfixes.db"
    _cvefixes_fixture(db)
    conn = sqlite3.connect(db)
    conn.execute("update file_change set filename = 'src/main.c'")
    conn.commit()
    conn.close()

    assert collect(db, limit=None) == []


def test_cvefixes_inspect_runs_without_a_real_database(tmp_path):
    """--inspect is the first thing to run on a real copy, so it must not
    depend on the schema it is meant to reveal."""
    db = tmp_path / "CVEfixes.db"
    _cvefixes_fixture(db)
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/dataset/collect_cvefixes.py"),
         "--db", str(db), "--inspect"],
        capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
    assert "method_change" in r.stdout


# ------------------------------------------------------------ record shape

def test_records_round_trip_through_jsonl(tmp_path):
    from scripts.dataset.record import Record, read_jsonl, write_jsonl

    original = [Record(source="s", group="g", path="p", language="python",
                       code="x = 1\n", cwes=["CWE-89"], is_vulnerable=True)]
    path = tmp_path / "r.jsonl"
    assert write_jsonl(original, path) == 1
    back = list(read_jsonl(path))
    assert back == original
    assert json.loads(path.read_text())["cwes"] == ["CWE-89"]
