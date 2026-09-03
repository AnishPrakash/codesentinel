"""Runs every applicable rule and returns findings, worst first."""
from __future__ import annotations

from pathlib import Path

from ..deps.firewall import scan_dependencies
from ..models import Finding, Language, Tier
from ..parser import ParsedSource
from .extended_js import JS_EXTENDED, JS_EXTENDED2
from .extended_python import PYTHON_EXTENDED, PYTHON_EXTENDED2
from .java_rules import JAVA_RULES
from .js_rules import JS_RULES
from .python_rules import PYTHON_RULES

ALL_RULES = (PYTHON_RULES + JS_RULES + PYTHON_EXTENDED + JS_EXTENDED
             + PYTHON_EXTENDED2 + JS_EXTENDED2 + JAVA_RULES)

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
    ("CS014", "Unsafe deserialization",       "CWE-502",  "A08:2021", "deterministic"),
    ("CS015", "Certificate validation off",   "CWE-295",  "A02:2021", "deterministic"),
    ("CS016", "Cleartext transmission",       "CWE-319",  "A02:2021", "deterministic"),
    ("CS017", "Sensitive data in logs",       "CWE-532",  "A09:2021", "deterministic"),
    # --- advisory: a heuristic about something absent ---
    ("CS010", "No CSRF protection",           "CWE-352",  "A01:2021", "advisory"),
    ("CS011", "No rate limiting",             "CWE-770",  "A04:2021", "advisory"),
    ("CS012", "Unvalidated input to a sink",  "CWE-20",   "A03:2021", "advisory"),
    ("CS013", "Check-then-use race",          "CWE-367",  "A04:2021", "advisory"),
]

DETERMINISTIC = [c for c in COVERED if c[4] == "deterministic"]
ADVISORY = [c for c in COVERED if c[4] == "advisory"]


def rules_for(language: Language) -> list[str]:
    """Which class ids actually have a matcher for this language.

    Java coverage is a subset, and the honest thing is to be able to print
    which subset rather than implying parity.
    """
    ids = {r.rule_id for r in ALL_RULES if language in r.languages}
    if language is not Language.JAVA:
        ids.add("CS006")            # the firewall is manifest-driven, not a Rule
    return sorted(ids)


def coverage_statement(language: Language | None = None) -> str:
    """Shown on every response, including clean ones. A green tick with no
    scope statement is how a scanner becomes a false sense of security."""
    if language is not None:
        covered = set(rules_for(language))
        det = [c for c in DETERMINISTIC if c[0] in covered]
        adv = [c for c in ADVISORY if c[0] in covered]
        scope = f" for {language.value}"
    else:
        det, adv, scope = DETERMINISTIC, ADVISORY, ""

    advisory_part = (
        f" and {len(adv)} advisory heuristics "
        f"({', '.join(n for _, n, _, _, _ in adv)}). "
        "Advisories are hints, not findings."
        if adv else
        # "0 advisory heuristics ()" is how a coverage statement stops being read.
        " and no advisory heuristics apply to it."
    )
    return (
        f"Checked {len(det)} deterministic classes{scope} "
        f"({', '.join(n for _, n, _, _, _ in det)})"
        f"{advisory_part} This is not a security audit - "
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
