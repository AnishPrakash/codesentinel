"""Runs every applicable rule and returns findings, worst first."""
from __future__ import annotations

from pathlib import Path

from ..deps.firewall import scan_dependencies
from ..models import Finding, Tier
from ..parser import ParsedSource
from .extended_js import JS_EXTENDED
from .extended_python import PYTHON_EXTENDED
from .js_rules import JS_RULES
from .python_rules import PYTHON_RULES

ALL_RULES = PYTHON_RULES + JS_RULES + PYTHON_EXTENDED + JS_EXTENDED

# The single source of truth for what this tool claims to check.
# (rule_id, name, cwe, owasp, tier)
COVERED: list[tuple[str, str, str, str, str]] = [
    # --- deterministic: a structural pattern is present ---
    ("CS001", "Hardcoded credentials",        "CWE-798",  "A07:2021", "deterministic"),
    ("CS002", "SQL injection",                "CWE-89",   "A03:2021", "deterministic"),
    ("CS003", "Command injection",            "CWE-78",   "A03:2021", "deterministic"),
    ("CS004", "Weak cryptography",            "CWE-327",  "A02:2021", "deterministic"),
    ("CS005", "Missing route authentication", "CWE-306",  "A01:2021", "deterministic"),
    ("CS006", "Unrecognised dependency",      "CWE-1104", "A06:2021", "deterministic"),
    ("CS007", "Cross-site scripting",         "CWE-79",   "A03:2021", "deterministic"),
    ("CS008", "Path traversal",               "CWE-22",   "A01:2021", "deterministic"),
    ("CS009", "Overly permissive config",     "CWE-942",  "A05:2021", "deterministic"),
    # --- advisory: a heuristic about something absent ---
    ("CS010", "No CSRF protection",           "CWE-352",  "A01:2021", "advisory"),
    ("CS011", "No rate limiting",             "CWE-770",  "A04:2021", "advisory"),
    ("CS012", "Unvalidated input to a sink",  "CWE-20",   "A03:2021", "advisory"),
    ("CS013", "Check-then-use race",          "CWE-367",  "A04:2021", "advisory"),
]

DETERMINISTIC = [c for c in COVERED if c[4] == "deterministic"]
ADVISORY = [c for c in COVERED if c[4] == "advisory"]


def coverage_statement() -> str:
    """Shown on every response, including clean ones. A green tick with no
    scope statement is how a scanner becomes a false sense of security."""
    return (
        f"Checked {len(DETERMINISTIC)} deterministic classes "
        f"({', '.join(n for _, n, _, _, _ in DETERMINISTIC)}) "
        f"and {len(ADVISORY)} advisory heuristics "
        f"({', '.join(n for _, n, _, _, _ in ADVISORY)}). "
        "Advisories are hints, not findings. This is not a security audit - "
        "anything outside these classes was not examined."
    )


def run_rules(ps: ParsedSource, local_root: Path | None = None) -> list[Finding]:
    """Run every applicable rule.

    `local_root` is the directory of the file being scanned, when it is known.
    The dependency firewall uses it to tell the user's own modules apart from
    packages; everything else ignores it.
    """
    findings: list[Finding] = []
    for rule in ALL_RULES:
        if ps.language in rule.languages:
            findings.extend(rule.run(ps))
    findings.extend(scan_dependencies(ps, local_root))
    # Deterministic findings always sort above advisories, then by severity.
    findings.sort(key=lambda f: (f.tier is Tier.ADVISORY, -int(f.severity), f.line))
    return findings
