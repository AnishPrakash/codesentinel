from ..models import Finding
from .socratic import attach_question
from .templates import explain


def enrich(findings: list[Finding]) -> list[Finding]:
    return [attach_question(explain(f)) for f in findings]
