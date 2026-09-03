import json
from pathlib import Path

from typer.testing import CliRunner

from codesentinel.cli import app

runner = CliRunner()
FIX = Path(__file__).parent / "fixtures"


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "codesentinel" in r.stdout


def test_rules_lists_every_class_with_its_tier():
    r = runner.invoke(app, ["rules"])
    assert r.exit_code == 0
    for n in range(1, 14):
        assert f"CS{n:03d}" in r.stdout
    assert "finding" in r.stdout and "advisory" in r.stdout


def test_advisories_never_change_the_exit_code():
    """A CI job must not fail because we could not see a rate limiter that lives
    in the ingress config."""
    src = FIX / "advisory_only"
    r = runner.invoke(app, ["scan", str(src), "--fail-on", "low"])
    assert r.exit_code == 0
    assert "ADVISORY" in r.stdout


def test_scan_vulnerable_exits_1():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable")])
    assert r.exit_code == 1
    assert "CRITICAL" in r.stdout


def test_scan_clean_exits_0():
    r = runner.invoke(app, ["scan", str(FIX / "clean")])
    assert r.exit_code == 0


def _flat(text: str) -> str:
    """Rich hard-wraps to the terminal width, so assert against unwrapped text."""
    import re
    return re.sub(r"\s+", " ", text)


def test_coverage_always_printed():
    r = runner.invoke(app, ["scan", str(FIX / "clean")])
    assert "not a security audit" in _flat(r.stdout)


def test_clean_directory_reports_nothing_at_all():
    """The false-positive test that matters: structurally identical safe code."""
    r = runner.invoke(app, ["scan", str(FIX / "clean")])
    assert "No findings." in r.stdout


def test_fail_on_none_never_fails():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable"), "--fail-on", "none"])
    assert r.exit_code == 0


def test_json_is_valid_and_has_coverage():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py"),
                            "-f", "json"])
    body = json.loads(r.stdout)
    assert "not a security audit" in body["coverage"]
    assert body["files"][0]["findings"]


def test_json_findings_carry_tier():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py"),
                            "-f", "json"])
    body = json.loads(r.stdout)
    for f in body["files"][0]["findings"]:
        assert f["tier"] in ("deterministic", "advisory")
        assert f["cwe"].startswith("CWE-")


def test_markdown_format():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py"),
                            "-f", "markdown"])
    assert "# CodeSentinel report" in r.stdout
    assert "CWE-" in r.stdout


def test_secrets_never_printed_in_full():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable")])
    assert "AKIAIOSFODNN7EXAMPLE" not in r.stdout


def test_fix_hidden_behind_the_gate():
    """A critical finding must show its question, not its fix."""
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py")])
    assert "Before the fix:" in r.stdout
    assert "cs learn" in r.stdout


def test_show_fix_bypasses_the_gate():
    r = runner.invoke(app, ["scan", str(FIX / "vulnerable" / "flask_app.py"),
                            "--show-fix"])
    assert "Before the fix:" not in r.stdout


def test_learn_unlocks_on_a_correct_answer():
    good = ("it returns the other user's record because the query looks up the row "
            "by the id in the URL and never checks ownership against the logged in user")
    r = runner.invoke(app, ["learn", "CS005"], input=good + "\n")
    assert r.exit_code == 0
    assert "Fix" in r.stdout


def test_learn_rejects_a_guess_three_times():
    r = runner.invoke(app, ["learn", "CS005"], input="it is bad\nstill bad\nbad\n")
    assert r.exit_code == 1


def test_learn_has_no_check_for_an_advisory():
    assert runner.invoke(app, ["learn", "CS010"]).exit_code == 1


def test_explain_unknown_rule():
    assert runner.invoke(app, ["explain", "CS999"]).exit_code == 1


def test_explain_known_rule():
    r = runner.invoke(app, ["explain", "CS002"])
    assert r.exit_code == 0
    assert "CWE-89" in r.stdout


def test_help_renders_for_every_command():
    """`--help` must not traceback.

    typer 0.15 against click 8.3 raised
    `Parameter.make_metavar() missing 1 required positional argument: 'ctx'`
    on every help screen. Nothing else in the suite touched help rendering, so
    the whole test suite passed while the first command a new user types was
    broken. Help is part of the interface.
    """
    from typer.testing import CliRunner

    from codesentinel.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output

    for command in ("scan", "explain", "learn", "rules", "progress",
                    "history", "install-hook", "install-model", "version"):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, f"{command} --help: {result.output}"
        assert "Usage:" in result.output, command


def test_help_does_not_hardcode_a_class_count():
    """A count in a help string is a claim about coverage.

    `learn` advertised CS001..CS009 and `explain` CS001..CS013 for weeks after
    there were seventeen classes. Nobody re-reads a help string when adding a
    rule, so the string has to be derived from the rule table.

    Asserted against the derived constant and the rendered command help, not
    against the argument panel: typer does not render Argument help at all
    against click 8.5, so an assertion on that panel tests typer's version, not
    ours.
    """
    from typer.testing import CliRunner

    from codesentinel.cli import _RULE_ID_HELP, app
    from codesentinel.rules.engine import COVERED

    ids = sorted(c[0] for c in COVERED)
    assert str(len(COVERED)) in _RULE_ID_HELP
    assert ids[0] in _RULE_ID_HELP and ids[-1] in _RULE_ID_HELP
    assert "CS009" not in _RULE_ID_HELP or ids[-1] == "CS009"
    assert "CS013" not in _RULE_ID_HELP or ids[-1] == "CS013"

    # And it has to reach a user, not just exist.
    runner = CliRunner()
    for command in ("explain", "learn"):
        out = runner.invoke(app, [command, "--help"]).output
        # Rich wraps the help body, so compare on collapsed whitespace.
        flat = " ".join(out.split())
        assert " ".join(_RULE_ID_HELP.split()) in flat, f"{command} --help: {out}"
