"""The demo folder is a deliverable, so it gets tests.

A demo that stops finding anything is not a failing test in any other file -
it is a silent, live, in-front-of-judges failure. These assertions pin what
each demo file is supposed to show, so a rule change that guts the
demonstration breaks CI instead of the presentation.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from codesentinel.languages import detect_language
from codesentinel.models import Tier
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules

DEMO = Path(__file__).resolve().parents[1] / "demo"


def scan(path: Path):
    code = path.read_text(encoding="utf-8")
    parsed = parse(code, detect_language(path.name, code))
    # local_root matters: the dependency firewall uses it to tell the user's own
    # modules apart from packages, and CS006 is the whole point of deps_demo.py.
    return parsed, run_rules(parsed, local_root=path.parent)


# What each file exists to demonstrate. Not the full set it happens to find -
# only the classes the demo would be pointless without, so ordinary rule
# tuning does not turn this into a file people edit without reading.
EXPECTED: dict[str, set[str]] = {
    "invoices.py": {"CS001", "CS002", "CS003", "CS005"},
    "orders.js": {"CS001", "CS002", "CS005", "CS007"},
    "InvoiceController.java": {"CS001", "CS002", "CS005"},
    "deps_demo.py": {"CS006"},
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_demo_file_still_demonstrates_its_classes(name: str) -> None:
    path = DEMO / name
    assert path.exists(), f"{name} is referenced by the demo script but missing"

    _, findings = scan(path)
    found = {f.rule_id for f in findings}
    missing = EXPECTED[name] - found
    assert not missing, f"{name} no longer finds {sorted(missing)} (found {sorted(found)})"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_demo_file_has_a_deterministic_finding(name: str) -> None:
    """Advisories alone are not a demo.

    A file whose findings are all advisories demonstrates the tool guessing,
    not the tool being right, and that is the opposite of the point.
    """
    _, findings = scan(DEMO / name)
    deterministic = [f for f in findings if f.tier is Tier.DETERMINISTIC]
    assert deterministic, f"{name} produces only advisories"


def test_every_supported_language_is_represented() -> None:
    """The demo has to cover what the pitch claims it covers."""
    languages = {scan(DEMO / name)[0].language.value for name in EXPECTED}
    assert {"python", "javascript", "java"} <= languages, languages


def test_no_demo_finding_echoes_a_full_credential() -> None:
    """The redaction promise applies to the files we hand people to look at.

    demo/ contains real-shaped keys on purpose. If the scanner printed one back
    intact, the demo would be a live demonstration of the bug it claims to
    prevent.
    """
    for name in EXPECTED:
        _, findings = scan(DEMO / name)
        for finding in findings:
            if finding.rule_id != "CS001":
                continue
            assert "AKIAIOSFODNN7EXAMPLE" not in finding.snippet, finding.snippet
            assert "*" in finding.snippet or len(finding.snippet) < 24, finding.snippet
