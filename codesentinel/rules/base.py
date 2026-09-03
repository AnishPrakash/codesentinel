"""A Rule carries its own grounding. Detection and citation cannot drift apart
because they are the same object."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator

from ..models import Finding, Language, Severity, Tier
from ..parser import ParsedSource

# A matcher yields (node, evidence) or (node, evidence, cwe, owasp).
#
# Evidence is free text used in the explanation - the concrete operator or
# callee that triggered the match. The optional third and fourth elements let a
# matcher cite a MORE PRECISE standard than its rule's default.
#
# That exists because one rule id can legitimately cover several distinct
# weaknesses. CS009 fires on wildcard CORS, on debug=True and on a world-
# writable chmod; those are CWE-942, CWE-489 and CWE-732 respectively, and
# citing "Permissive Cross-domain Policy" for a debug console is simply wrong.
# The rule-carries-its-own-CWE principle is about detection and citation being
# decided together, not about there being exactly one citation per rule - and
# the matcher is the thing that knows which case it matched.
Matcher = Callable[[ParsedSource], Iterator[tuple]]


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

        matches: list[tuple] = []
        seen: set[tuple[int, int]] = set()
        for match in self.matcher(ps):
            node, evidence = match[0], match[1]
            key = (node.start_byte, node.end_byte)
            if key in seen:
                continue
            seen.add(key)
            matches.append(match)

        out: list[Finding] = []
        for match in _innermost(matches):
            node, evidence = match[0], match[1]
            # A matcher may cite something more precise than the rule default.
            cwe = match[2] if len(match) > 2 and match[2] else self.cwe
            owasp = match[3] if len(match) > 3 and match[3] else self.owasp
            snippet = ps.snippet(node)
            out.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                cwe=cwe,
                owasp=owasp,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                column=node.start_point[1],
                snippet=redact(snippet) if self.redact else snippet,
                language=ps.language,
                tier=self.tier,
                explanation=evidence,      # replaced by the explain layer
            ))
        return out


def _innermost(matches: list[tuple]) -> list[tuple]:
    """Drop a match whose span strictly contains another match of the same rule.

    Expression trees nest: `app.get('/x', (req, res) => db.query(...))` is a
    call_expression whose text contains another call_expression, so a matcher
    that reads node text fires on both. The inner node is the precise one, so
    the outer is noise - reporting the same flaw twice at two indentations is
    exactly the kind of thing that makes people stop reading a scanner.
    """
    spans = [(m[0].start_byte, m[0].end_byte) for m in matches]
    keep = []
    for i, match in enumerate(matches):
        a, b = spans[i]
        contains_another = any(
            j != i and a <= c and d <= b and (d - c) < (b - a)
            for j, (c, d) in enumerate(spans)
        )
        if not contains_another:
            keep.append(match)
    return keep


def redact(text: str) -> str:
    """Never echo a full credential back. The scanner handles secrets by
    definition - leaking them in its own output would be absurd."""

    def mask(m: "re.Match") -> str:
        v = m.group(0)
        return v if len(v) <= 8 else f"{v[:4]}{'*' * (len(v) - 8)}{v[-4:]}"

    return re.sub(r"""(?<=["'])[^"']{9,}(?=["'])""", mask, text)


def looks_like_request_target(name_context: str, call_context: str) -> bool:
    """Is this http:// string actually a request target?

    Two ways to tell, and neither may use \b anchors on the identifier: a name
    like REPORT_ENDPOINT or base_url has word characters either side of the
    keyword, so a leading \b never fires. That exact bug silently disabled this
    rule the first time it was written.
    """
    import re as _re
    NAME_HINT = _re.compile(
        r"(?i)(url|uri|endpoint|host|webhook|api|base|server|origin|callback|link)")
    CALL_HINT = _re.compile(
        r"(?i)(requests|httpx|urllib|urlopen|aiohttp|session|client|fetch|axios|"
        r"got|superagent|xmlhttprequest|httpclient|httpurlconnection|resttemplate|"
        r"okhttp|webclient|openconnection|\.get\(|\.post\(|\.put\(|\.delete\()")
    return bool(NAME_HINT.search(name_context) or CALL_HINT.search(call_context))
