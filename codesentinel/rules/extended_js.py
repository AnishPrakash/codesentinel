"""CS007-CS013 for JavaScript. Same ids, same CWEs, different syntax."""
from __future__ import annotations

import re
from typing import Iterator

from tree_sitter import Node

from ..models import Language, Severity, Tier
from ..parser import ParsedSource, enclosing_function, walk
from .base import Rule

JS = frozenset({Language.JAVASCRIPT})

REQ_SOURCE_JS = re.compile(r"req\.(params|query|body|headers|cookies)")
SANITISER_JS = re.compile(
    r"(?i)\b(escape|sanitize|DOMPurify|encodeURIComponent|validator\.|"
    r"path\.normalize|path\.basename|joi\.|zod\.|express-validator)\b")


def _tainted_js(ps: ParsedSource, node: Node) -> bool:
    return bool(REQ_SOURCE_JS.search(ps.text(node)))


# ----------------------------------------------------------- CS007 XSS (JS)

def match_xss_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        text = ps.text(node)

        if node.type == "assignment_expression" and re.search(
                r"\.innerHTML\s*=", text):
            rhs = node.child_by_field_name("right")
            if rhs is not None and rhs.type == "template_string" and "${" in ps.text(rhs):
                yield node, ("innerHTML is assigned a template literal that interpolates "
                             "a variable")
            elif rhs is not None and rhs.type not in ("string", "template_string"):
                yield node, ("innerHTML is assigned a value that is not a literal, so "
                             "any markup in it is parsed and executed")

        elif node.type == "jsx_attribute" and "dangerouslySetInnerHTML" in text:
            if not SANITISER_JS.search(text):
                yield node, ("dangerouslySetInnerHTML bypasses React's escaping and no "
                             "sanitiser is applied to the value")

        elif node.type == "call_expression":
            if re.search(r"document\.write\s*\(", text) and _tainted_js(ps, node):
                yield node, "document.write() is called with request data"
            elif re.search(r"\bres\.send\s*\(", text) and "${" in text \
                    and _tainted_js(ps, node) and not SANITISER_JS.search(text):
                yield node, ("an HTML response is built by interpolating request data "
                             "with no escaping")


# ------------------------------------------------- CS008 path traversal (JS)

FILE_SINK_JS = re.compile(
    r"(?i)\b(fs\.(readFile|readFileSync|createReadStream|writeFile|unlink)|"
    r"res\.sendFile|res\.download)\b")


def match_path_traversal_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node)
        if not FILE_SINK_JS.search(text) or not _tainted_js(ps, node):
            continue
        scope = ps.text(enclosing_function(node) or node)
        if SANITISER_JS.search(scope):
            continue
        yield node, ("a file path is built from req data with no normalisation, so ../ "
                     "sequences resolve outside the intended directory")


# ------------------------------------------ CS009 permissive config (JS)

def match_permissive_config_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        text = ps.text(node)
        if node.type != "call_expression":
            continue
        if re.search(r"\bcors\s*\(", text):
            if re.search(r"""origin\s*:\s*["']\*["']|origin\s*:\s*true""", text):
                if re.search(r"credentials\s*:\s*true", text):
                    yield node, ("CORS allows every origin *and* credentials, so any "
                                 "site can make authenticated requests as your users")
                else:
                    yield node, "CORS is open to every origin"
        elif re.search(
                r"""setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*""",
                text):
            yield node, "Access-Control-Allow-Origin is set to *"
        elif re.search(r"\bfs\.chmod(Sync)?\s*\(", text) and re.search(r"0o?7[0-7]7", text):
            yield node, "a file is made world-writable"


# =====================================================================
#  ADVISORIES
# =====================================================================

CSRF_PRESENT_JS = re.compile(r"(?i)(csurf|csrf|doubleCsrf)")
LIMITER_PRESENT_JS = re.compile(r"(?i)(rateLimit|express-rate-limit|throttle|slowDown)")
AUTH_ROUTE_JS = re.compile(r"(?i)['\"`]/[^'\"`]*(login|signin|register|signup|auth|"
                           r"token|password|reset|otp|verify)")
STATE_CHANGING_JS = re.compile(r"(?i)\b(app|router)\.(post|put|patch|delete)\s*\(")
SINK_JS = re.compile(r"(?i)\b(query|execute|exec|eval|readFile|writeFile|sendFile)\b")


def match_csrf_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    if CSRF_PRESENT_JS.search(ps.code):
        return
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node).strip()
        if STATE_CHANGING_JS.match(text):
            yield node, ("this route changes state and no CSRF middleware appears in "
                         "this file - it may be configured elsewhere, so check")


def match_rate_limit_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    if LIMITER_PRESENT_JS.search(ps.code):
        return
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node)
        if STATE_CHANGING_JS.match(text.strip()) and AUTH_ROUTE_JS.search(text):
            yield node, ("an authentication route with no rate limit visible in this "
                         "file - a proxy may already be limiting it")


def match_unvalidated_input_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("function_declaration", "arrow_function",
                             "function_expression"):
            continue
        body = ps.text(node)
        if not (REQ_SOURCE_JS.search(body) and SINK_JS.search(body)):
            continue
        if SANITISER_JS.search(body):
            continue
        yield node, ("request data reaches a sensitive operation in this handler and no "
                     "validation or escaping call appears between them")


def match_toctou_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("function_declaration", "arrow_function",
                             "function_expression"):
            continue
        body = ps.text(node)
        check = re.search(r"fs\.existsSync\s*\(\s*([\w.\[\]]+)", body)
        if check and re.search(
                rf"fs\.(readFile|writeFile|open)\w*\s*\(\s*{re.escape(check.group(1))}",
                body):
            yield node, (f"`{check.group(1)}` is checked with existsSync and then opened - "
                         "another process can replace the file in between")


JS_EXTENDED: list[Rule] = [
    Rule("CS007", "Cross-site scripting", Severity.CRITICAL,
         "CWE-79", "A03:2021 - Injection", JS, match_xss_js),
    Rule("CS008", "Path built from user input", Severity.HIGH,
         "CWE-22", "A01:2021 - Broken Access Control", JS, match_path_traversal_js),
    Rule("CS009", "Overly permissive configuration", Severity.HIGH,
         "CWE-942", "A05:2021 - Security Misconfiguration", JS,
         match_permissive_config_js),

    Rule("CS010", "No CSRF protection visible", Severity.LOW,
         "CWE-352", "A01:2021 - Broken Access Control", JS, match_csrf_js,
         tier=Tier.ADVISORY),
    Rule("CS011", "No rate limit visible on an auth route", Severity.LOW,
         "CWE-770", "A04:2021 - Insecure Design", JS, match_rate_limit_js,
         tier=Tier.ADVISORY),
    Rule("CS012", "Request data reaches a sink unvalidated", Severity.LOW,
         "CWE-20", "A03:2021 - Injection", JS, match_unvalidated_input_js,
         tier=Tier.ADVISORY),
    Rule("CS013", "Check-then-use race", Severity.LOW,
         "CWE-367", "A04:2021 - Insecure Design", JS, match_toctou_js,
         tier=Tier.ADVISORY),
]
