"""CWE to CodeSentinel class. The label contract for training.

This lives in the package, not in the training scripts, for the same reason the
alias table does: the dataset builder and anything that reads a model's output
must agree on what column 3 means. Two copies drift; one cannot.

A CWE that maps to nothing is dropped from training rather than forced into the
nearest class. A mislabelled sample is worse than a missing one - it teaches the
model that a real vulnerability of one kind is evidence for another.
"""
from __future__ import annotations

# Primary CWE first, then the near-synonyms datasets actually use.
CLASS_TO_CWES: dict[str, set[str]] = {
    "CS001": {"CWE-798", "CWE-259", "CWE-321", "CWE-256", "CWE-522"},
    "CS002": {"CWE-89", "CWE-564", "CWE-943"},
    "CS003": {"CWE-78", "CWE-77", "CWE-88", "CWE-95", "CWE-94"},
    "CS004": {"CWE-327", "CWE-326", "CWE-328", "CWE-330", "CWE-338",
              "CWE-916", "CWE-916", "CWE-780", "CWE-696"},
    "CS005": {"CWE-306", "CWE-862", "CWE-285", "CWE-639", "CWE-284"},
    "CS006": {"CWE-1104", "CWE-1035", "CWE-937", "CWE-829"},
    "CS007": {"CWE-79", "CWE-80", "CWE-83", "CWE-116"},
    "CS008": {"CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73"},
    "CS009": {"CWE-942", "CWE-732", "CWE-16", "CWE-15", "CWE-1004", "CWE-614"},
    "CS014": {"CWE-502", "CWE-915"},
    "CS015": {"CWE-295", "CWE-297", "CWE-599", "CWE-296"},
    "CS016": {"CWE-319", "CWE-311", "CWE-312", "CWE-523"},
    "CS017": {"CWE-532", "CWE-209", "CWE-215", "CWE-359"},
}

CWE_TO_CLASS: dict[str, str] = {
    cwe: cls for cls, cwes in CLASS_TO_CWES.items() for cwe in cwes
}


def normalise_cwe(raw: str | int) -> str:
    """`89`, `'89'`, `'CWE-89'`, `'cwe_89'` all mean CWE-89."""
    s = str(raw).strip().upper().replace("_", "-")
    if s.startswith("CWE-"):
        s = s[4:]
    s = s.lstrip("-")
    digits = "".join(ch for ch in s if ch.isdigit())
    return f"CWE-{digits}" if digits else ""


def class_for_cwe(raw: str | int) -> str | None:
    """The CodeSentinel class this CWE trains, or None if we do not cover it."""
    return CWE_TO_CLASS.get(normalise_cwe(raw))


def label_vector(cwes: list[str], class_order: list[str]) -> list[int]:
    """Multi-hot label in the model's output order.

    A sample can carry more than one CWE - a handler can be both an injection
    and a missing-auth case - so this is multi-label, not multi-class, which is
    why the network ends in sigmoid rather than softmax.
    """
    positive = {c for c in (class_for_cwe(x) for x in cwes) if c}
    return [1 if cls in positive else 0 for cls in class_order]
