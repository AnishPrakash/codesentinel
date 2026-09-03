from contextlib import contextmanager
from pathlib import Path

from typer.testing import CliRunner

from codesentinel import ledger
from codesentinel.cli import app
from codesentinel.explain import enrich
from codesentinel.models import Language, ScanResult
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules

runner = CliRunner()
FIX = Path(__file__).parent / "fixtures"

# conftest.py points CODESENTINEL_HOME at a temp dir for every test.


def _result() -> ScanResult:
    code = (FIX / "vulnerable" / "flask_app.py").read_text()
    ps = parse(code, Language.PYTHON)
    return ScanResult(path="demo.py", language=Language.PYTHON,
                      line_count=code.count("\n") + 1, elapsed_ms=1.0,
                      findings=enrich(run_rules(ps)))


def test_record_and_read_back():
    scan_id = ledger.record_scan(_result())
    assert scan_id is not None
    rows = ledger.history()
    assert rows and rows[0]["path"] == "demo.py"
    assert rows[0]["finding_count"] > 0


def test_no_code_reaches_the_ledger():
    """The privacy claim, asserted against the database file itself."""
    ledger.record_scan(_result())
    from codesentinel.config import get_settings
    blob = get_settings().ledger_path.read_bytes().decode("utf-8", "replace")
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "SELECT * FROM users" not in blob
    assert "hunter2" not in blob


def test_comprehension_upsert():
    ledger.record_attempt("CS005", passed=False)
    ledger.record_attempt("CS005", passed=True)
    rows = {r["rule_id"]: r for r in ledger.progress()}
    assert rows["CS005"]["attempts"] == 2
    assert rows["CS005"]["passes"] == 1
    assert rows["CS005"]["mastered"] is True
    assert rows["CS001"]["mastered"] is False


def test_mastered_rules():
    assert ledger.mastered_rules() == set()
    ledger.record_attempt("CS002", passed=True)
    assert ledger.mastered_rules() == {"CS002"}


def test_rule_frequency():
    ledger.record_scan(_result())
    freq = ledger.rule_frequency()
    assert freq and freq[0]["hits"] >= 1
    assert all(r["cwe"].startswith("CWE-") for r in freq)


def test_scan_stops_gating_a_mastered_class():
    before = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py")])
    assert "Before the fix:" in before.stdout

    for rid in ("CS001", "CS002", "CS004", "CS005"):
        ledger.record_attempt(rid, passed=True)

    after = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py")])
    assert "Before the fix:" not in after.stdout
    assert "Not re-asking" in after.stdout


def test_no_ledger_flag_writes_nothing():
    runner.invoke(app, ["scan", str(FIX / "vulnerable"), "--no-ledger"])
    assert ledger.history() == []


def test_progress_command():
    """Asserted against the taxonomy, not a hardcoded count - adding a class
    should not break this test, only change the denominator."""
    from codesentinel.rules.engine import DETERMINISTIC
    ledger.record_attempt("CS002", passed=True)
    r = runner.invoke(app, ["progress"])
    assert r.exit_code == 0
    assert f"1 of {len(DETERMINISTIC)}" in r.stdout


def test_history_command():
    ledger.record_scan(_result())
    r = runner.invoke(app, ["history"])
    assert r.exit_code == 0
    assert "demo.py" in r.stdout


def test_reset_wipes_everything():
    ledger.record_scan(_result())
    ledger.record_attempt("CS002", passed=True)
    assert ledger.reset() is True
    assert ledger.history() == []
    assert ledger.mastered_rules() == set()


def test_everything_survives_a_broken_ledger(monkeypatch):
    """A read-only or corrupt ledger degrades the tool, never breaks a scan."""
    @contextmanager
    def broken():
        yield None

    monkeypatch.setattr("codesentinel.ledger.store.connect", broken)
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable")])
    assert r.exit_code == 1          # findings still reported
    assert "CRITICAL" in r.stdout
