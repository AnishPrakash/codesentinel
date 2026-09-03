"""A Rule carries its own grounding. Detection and citation cannot drift apart
because they are the same object."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator

from tree_sitter import Node

from ..models import Finding, Language, Severity, Tier
from ..parser import ParsedSource

# A matcher yields (node, evidence) pairs. Evidence is free text used in the
# explanation - e.g. the concrete operator or callee that triggered the match.
Matcher = Callable[[ParsedSource], Iterator[tuple[Node, str]]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    owasp: str
    languages: frozenset[Language]
    matcher: Matcher
    redact: bool = False              # true for credential rules
    tier: Tier = Tier.DETERMINISTIC   # advisory rules assert less, see models.py

    def run(self, ps: ParsedSource) -> list[Finding]:
        if ps.language not in self.languages:
            return []

        matches: list[tuple[Node, str]] = []
        seen: set[tuple[int, int]] = set()
        for node, evidence in self.matcher(ps):
            key = (node.start_byte, node.end_byte)
            if key in seen:
                continue
            seen.add(key)
            matches.append((node, evidence))

        out: list[Finding] = []
        for node, evidence in _innermost(matches):
            snippet = ps.snippet(node)
            out.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                cwe=self.cwe,
                owasp=self.owasp,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                column=node.start_point[1],
                snippet=redact(snippet) if self.redact else snippet,
                language=ps.language,
                tier=self.tier,
                explanation=evidence,      # replaced by the explain layer
            ))
        return out


def _innermost(matches: list[tuple[Node, str]]) -> list[tuple[Node, str]]:
    """Drop a match whose span strictly contains another match of the same rule.

    Expression trees nest: `app.get('/x', (req, res) => db.query(...))` is a
    call_expression whose text contains another call_expression, so a matcher
    that reads node text fires on both. The inner node is the precise one, so
    the outer is noise - reporting the same flaw twice at two indentations is
    exactly the kind of thing that makes people stop reading a scanner.
    """
    spans = [(n.start_byte, n.end_byte) for n, _ in matches]
    keep = []
    for i, (node, evidence) in enumerate(matches):
        a, b = spans[i]
        contains_another = any(
            j != i and a <= c and d <= b and (d - c) < (b - a)
            for j, (c, d) in enumerate(spans)
        )
        if not contains_another:
            keep.append((node, evidence))
    return keep


def redact(text: str) -> str:
    """Never echo a full credential back. The scanner handles secrets by
    definition - leaking them in its own output would be absurd."""

    def mask(m: "re.Match") -> str:
        v = m.group(0)
        return v if len(v) <= 8 else f"{v[:4]}{'*' * (len(v) - 8)}{v[-4:]}"

    return re.sub(r"""(?<=["'])[^"']{9,}(?=["'])""", mask, text)
