"""Grades a free-text answer against the rubric. Deterministic and offline.

A keyword rubric is crude. It is also transparent, instant, and impossible to
jailbreak with 'ignore previous instructions' - which an LLM grader is not. Say
this plainly rather than overclaiming: we check that the answer contains the
mechanism, not that it is well written.
"""
from __future__ import annotations

import re

from .socratic import RUBRIC

MIN_WORDS = 8

HINTS: dict[str, list[str]] = {
    "CS001": ["Where else does this value still exist, besides the file you edited?",
              "What has to happen to the key itself?"],
    "CS002": ["What does the WHERE clause evaluate to for every row?",
              "How does a parameterised query treat the value differently?"],
    "CS003": ["What does the shell do when it meets a ; ?",
              "What changes when you pass a list of arguments instead?"],
    "CS004": ["How many guesses per second can an attacker make?"],
    "CS005": ["What does the handler return for that id?",
              "Whose record is it?",
              "What is never compared against the logged-in user?"],
    "CS006": ["What can an attacker do with a name nobody owns?",
              "What command does the developer run next?"],
    "CS007": ["What does the browser do with a tag it finds in the value?",
              "Who is looking at the page when it runs?"],
    "CS008": ["Where does the path end up pointing?",
              "When are the ../ segments actually collapsed?"],
    "CS009": ["Which sites can now talk to your API?",
              "What does the browser attach to those requests?"],
}


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def grade(rule_id: str, answer: str) -> tuple[bool, str, list[str]]:
    """Returns (passed, feedback, missed_concepts)."""
    concepts = RUBRIC.get(rule_id)
    if not concepts:
        return True, "No rubric for this rule - unlocking the fix.", []

    text = _normalise(answer)
    if len(text.split()) < MIN_WORDS:
        return False, (
            "That is too short to show the mechanism. Describe what actually happens, "
            "in a sentence or two of your own words."
        ), []

    missed: list[int] = []
    for i, synonyms in enumerate(concepts):
        if not any(s in text for s in synonyms):
            missed.append(i)

    if not missed:
        return True, "That is right - you have identified the mechanism. Fix unlocked.", []

    hints = HINTS.get(rule_id, [])
    hint = " ".join(hints[i] for i in missed if i < len(hints))
    return False, f"Close, but something is missing. {hint}".strip(), [str(i) for i in missed]
