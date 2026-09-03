"""CS007-CS013 for Python. Deterministic first, advisories after the divider."""
from __future__ import annotations

import re
from typing import Iterator

from tree_sitter import Node

from ..models import Language, Severity, Tier
from ..parser import ParsedSource, enclosing_function, walk
from .base import Rule
from .python_rules import _callee

PY = frozenset({Language.PYTHON})

REQ_SOURCE = re.compile(
    r"(?i)(request\.(args|form|json|values|data|files|cookies|headers)|"
    r"\brequest\.get_json\b)")
ROUTE_PARAM = re.compile(r"<\w*:?(\w+)>")
SANITISER = re.compile(
    r"(?i)\b(escape|markupsafe\.escape|bleach\.clean|secure_filename|"
    r"os\.path\.basename|shlex\.quote|werkzeug\.utils\.secure_filename|"
    r"validate|is_valid|pydantic|marshmallow|cerberus)\b")


def _route_params(decorators: list[str]) -> set[str]:
    return {m.group(1) for d in decorators for m in ROUTE_PARAM.finditer(d)}


def _tainted(ps: ParsedSource, node: Node) -> bool:
    """Does this expression reference request data or a route parameter?"""
    text = ps.text(node)
    if REQ_SOURCE.search(text):
        return True
    fn = enclosing_function(node)
    if fn is None:
        return False
    parent = fn.parent
    decorators = [ps.text(d) for d in (parent.children if parent else [])
                  if d.type == "decorator"]
    names = _route_params(decorators)
    return any(re.search(rf"\b{re.escape(n)}\b", text) for n in names)


# ------------------------------------------------------- CS007 XSS (Python)

def match_xss_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call":
            continue
        callee = _callee(ps, node)
        args = node.child_by_field_name("arguments")
        arg_text = ps.text(args) if args is not None else ""

        if re.search(r"(?i)\brender_template_string\b", callee):
            if _tainted(ps, node) or re.search(r"[+%]|\.format\(|f[\"']", arg_text):
                yield node, ("a Jinja template is built from a string that includes "
                             "request data, so the input is compiled as template code")
        elif re.search(r"(?i)\b(Markup|markupsafe\.Markup)\b", callee):
            if _tainted(ps, node):
                yield node, ("Markup() marks a value as trusted HTML, and this value "
                             "comes from the request")
        elif re.search(r"(?i)\bHTMLResponse\b|\bHttpResponse\b", callee):
            if _tainted(ps, node) and not SANITISER.search(arg_text):
                yield node, ("an HTML response body is assembled from request data "
                             "with no escaping")


# --------------------------------------------- CS008 path traversal (Python)

FILE_SINK = re.compile(
    r"(?i)\b(open|send_file|send_from_directory|shutil\.copy|os\.remove|"
    r"os\.unlink|pathlib\.Path)\b")


def match_path_traversal_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call":
            continue
        callee = _callee(ps, node)
        if not FILE_SINK.search(callee):
            continue
        args = node.child_by_field_name("arguments")
        if args is None or not _tainted(ps, args):
            continue
        scope = ps.text(enclosing_function(node) or node)
        if SANITISER.search(scope):
            continue                      # basename/secure_filename present
        yield node, ("a file path is built from request data with no normalisation, "
                     "so ../ sequences resolve outside the intended directory")


# ------------------------------------ CS009 permissive configuration (Python)

def match_permissive_config_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    code = ps.code
    for node in walk(ps.root):
        text = ps.text(node)

        if node.type == "call":
            callee = _callee(ps, node)
            if re.search(r"(?i)\bos\.chmod\b", callee) and re.search(r"0o?7[0-7]7", text):
                yield node, "a file is made world-writable"
            elif re.search(r"(?i)\bapp\.run\b", callee) and re.search(
                    r"debug\s*=\s*True", text):
                yield node, ("the development server is started with debug=True, which "
                             "exposes an interactive console that executes code")

        if node.type in ("call", "assignment", "keyword_argument"):
            if re.search(r"""allow_origins\s*=\s*\[?\s*["']\*["']""", text):
                if re.search(r"allow_credentials\s*=\s*True", code):
                    yield node, ("CORS allows every origin *and* credentials, so any "
                                 "site can make authenticated requests as your users")
                else:
                    yield node, "CORS is open to every origin"


# =====================================================================
#  ADVISORIES - heuristics about absence. Never critical, never gated.
# =====================================================================

STATE_CHANGING = re.compile(r"(?i)methods\s*=\s*\[[^\]]*(POST|PUT|PATCH|DELETE)")
CSRF_PRESENT = re.compile(r"(?i)(csrf|CSRFProtect|csrf_token|flask_wtf)")
LIMITER_PRESENT = re.compile(r"(?i)(limiter|ratelimit|rate_limit|slowapi|throttle)")
AUTH_ROUTE = re.compile(r"(?i)/(login|signin|sign-in|register|signup|auth|token|"
                        r"password|reset|otp|verify)")


def match_csrf_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    if CSRF_PRESENT.search(ps.code):
        return                                    # protection is configured somewhere
    for node in walk(ps.root):
        if node.type != "decorated_definition":
            continue
        head = ps.text(node)
        if not STATE_CHANGING.search(head):
            continue
        yield node, ("this route changes state and no CSRF protection appears in this "
                     "file - it may be configured elsewhere, so check rather than assume")


def match_rate_limit_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    if LIMITER_PRESENT.search(ps.code):
        return
    for node in walk(ps.root):
        if node.type != "decorated_definition":
            continue
        head = ps.text(node)
        if not AUTH_ROUTE.search(head):
            continue
        yield node, ("an authentication route with no rate limit visible in this file - "
                     "credential stuffing is the usual consequence, but a reverse proxy "
                     "may already be limiting it")


DANGEROUS_SINK = re.compile(
    r"(?i)\b(execute|eval|exec|os\.system|subprocess|open|send_file|"
    r"render_template_string)\b")


def match_unvalidated_input_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    """Source and sink in the same function, no sanitiser between them.

    We cannot claim the input is unvalidated - only that we traced a path and
    saw nothing that looks like validation. That is exactly what the message says.
    """
    for node in walk(ps.root):
        if node.type not in ("function_definition",):
            continue
        body = ps.text(node)
        if not REQ_SOURCE.search(body):
            continue
        if not DANGEROUS_SINK.search(body):
            continue
        if SANITISER.search(body):
            continue
        yield node, ("request data reaches a sensitive operation in this function and "
                     "no validation or escaping call appears between them")


def match_toctou_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    """The narrow check-then-use shape: exists() then open() on the same name."""
    for node in walk(ps.root):
        if node.type != "function_definition":
            continue
        body = ps.text(node)
        check = re.search(
            r"(?i)(os\.path\.(exists|isfile)|Path\([^)]*\)\.exists)\s*\(\s*([\w.\[\]]+)",
            body)
        if not check:
            continue
        name = check.group(3)
        if not name:
            continue
        if re.search(rf"open\s*\(\s*{re.escape(name)}", body):
            yield node, (f"`{name}` is checked for existence and then opened - between "
                         "those two lines another process can replace the file")


PYTHON_EXTENDED: list[Rule] = [
    Rule("CS007", "Cross-site scripting", Severity.CRITICAL,
         "CWE-79", "A03:2021 - Injection", PY, match_xss_py),
    Rule("CS008", "Path built from user input", Severity.HIGH,
         "CWE-22", "A01:2021 - Broken Access Control", PY, match_path_traversal_py),
    Rule("CS009", "Overly permissive configuration", Severity.HIGH,
         "CWE-942", "A05:2021 - Security Misconfiguration", PY,
         match_permissive_config_py),

    Rule("CS010", "No CSRF protection visible", Severity.LOW,
         "CWE-352", "A01:2021 - Broken Access Control", PY, match_csrf_py,
         tier=Tier.ADVISORY),
    Rule("CS011", "No rate limit visible on an auth route", Severity.LOW,
         "CWE-770", "A04:2021 - Insecure Design", PY, match_rate_limit_py,
         tier=Tier.ADVISORY),
    Rule("CS012", "Request data reaches a sink unvalidated", Severity.LOW,
         "CWE-20", "A03:2021 - Injection", PY, match_unvalidated_input_py,
         tier=Tier.ADVISORY),
    Rule("CS013", "Check-then-use race", Severity.LOW,
         "CWE-367", "A04:2021 - Insecure Design", PY, match_toctou_py,
         tier=Tier.ADVISORY),
]
