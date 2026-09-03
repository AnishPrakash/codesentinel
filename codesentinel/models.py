"""Core types. Findings are facts; predictions are opinions. Different types,
deliberately, so one can never be rendered as the other."""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Language(str, enum.Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"


class Tier(str, enum.Enum):
    """How much the tool is willing to assert.

    DETERMINISTIC — a structural match. The pattern is present in the tree.
        Cited with a CWE, gated behind a comprehension question, counts toward
        the exit code and toward our published false-positive rate.

    ADVISORY — a heuristic, usually about something *absent* (no CSRF
        middleware, no rate limit, no sanitiser on a traced path). Absence is
        not provable from one file, so these are never critical, never gated,
        never counted in the exit code, and labelled "advisory" in the output.

    Keeping these apart is the whole reason we can publish a false-positive
    number at all. Collapsing them would make the number meaningless.
    """
    DETERMINISTIC = "deterministic"
    ADVISORY = "advisory"


@dataclass(frozen=True)
class Finding:
    """A deterministic structural match. Every field is reproducible by hand.

    rule_id, cwe and owasp are carried by the rule itself rather than looked up
    later, so grounding cannot drift from detection.
    """
    rule_id: str                 # CS001..CS013
    title: str
    severity: Severity
    cwe: str                     # "CWE-798"
    owasp: str                   # "A07:2021 - Identification and Authentication Failures"
    line: int                    # 1-indexed
    end_line: int
    column: int
    snippet: str                 # redacted where the match is a credential
    language: Language
    tier: Tier = Tier.DETERMINISTIC
    # filled by the explain layer
    explanation: str = ""
    attack: str = ""
    fix: str = ""
    question: str = ""           # "" when not gated, or already mastered
    # filled by the triage layer
    confidence: float = 1.0      # rules are always 1.0; the model only reorders

    @property
    def location(self) -> str:
        return f"{self.line}:{self.column}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = self.severity.label
        d["language"] = self.language.value
        d["tier"] = self.tier.value
        return d


@dataclass(frozen=True)
class Prediction:
    """A model opinion. Never carries a CWE and never names a specific flaw."""
    score: float
    label: str = "needs_review"
    note: str = (
        "This file resembles code that has had security problems, but no rule "
        "matched. Nothing specific was found - treat this as a prompt to look "
        "again, not as a finding."
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """One file's outcome. The CLI and the ledger both consume this."""
    path: str
    language: Language
    line_count: int
    elapsed_ms: float
    findings: list[Finding] = field(default_factory=list)
    prediction: Prediction | None = None

    @property
    def counts(self) -> dict[str, int]:
        out = {s.label.lower(): 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label.lower()] += 1
        return out

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language.value,
            "line_count": self.line_count,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
            "prediction": self.prediction.to_dict() if self.prediction else None,
        }
