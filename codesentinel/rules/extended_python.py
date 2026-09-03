"""CS007-CS013 for Python. Deterministic first, advisories after the divider."""
from __future__ import annotations

import re
from typing import Iterator

from tree_sitter import Node

from ..models import Language, Severity, Tier
from ..parser import ParsedSource, enclosing_function, walk
from .base import Rule, looks_like_request_target
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
                yield (node, "a file is made world-writable",
                       "CWE-732", "A01:2021 - Broken Access Control")
            elif re.search(r"(?i)\bapp\.run\b", callee) and re.search(
                    r"debug\s*=\s*True", text):
                yield (node, ("the development server is started with debug=True, which "
                              "exposes an interactive console that executes code"),
                       "CWE-489", "A05:2021 - Security Misconfiguration")

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


# =====================================================================
#  CS014-CS017 - deterministic classes added in the second pass.
#  These come from plan.md's pattern-feature table: unsafe deserialization,
#  disabled certificate validation, cleartext transport, and secrets in logs.
# =====================================================================

# ------------------------------------------- CS014 unsafe deserialization

def match_deserialization_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call":
            continue
        callee = _callee(ps, node)
        args = ps.text(node.child_by_field_name("arguments") or node)

        if re.search(r"(?i)\b(pickle|cPickle|_pickle|dill|shelve)\.(loads?|Unpickler)\b",
                     callee):
            yield node, ("pickle reconstructs objects by running the constructors named in "
                         "the data, so loading untrusted bytes runs untrusted code")
        elif re.search(r"(?i)\bmarshal\.loads?\b", callee):
            yield node, ("marshal deserialises Python bytecode objects and is documented "
                         "as unsafe for untrusted data")
        elif re.search(r"(?i)\byaml\.load\b", callee) and not re.search(
                r"(?i)(SafeLoader|BaseLoader|CSafeLoader)", args):
            yield node, ("yaml.load without SafeLoader lets the document name arbitrary "
                         "Python objects to construct")
        elif re.search(r"(?i)\bjsonpickle\.decode\b", callee):
            yield node, "jsonpickle.decode reconstructs arbitrary Python types from JSON"


# ------------------------------ CS015 certificate validation disabled (Python)

def match_tls_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        text = ps.text(node)
        if node.type == "call":
            callee = _callee(ps, node)
            args = ps.text(node.child_by_field_name("arguments") or node)
            if re.search(r"(?i)\b(requests|httpx|session)\.(get|post|put|patch|delete|"
                         r"head|request)\b", callee) or re.search(
                             r"(?i)\b(Client|Session)\b", callee):
                if re.search(r"verify\s*=\s*False", args):
                    yield node, ("verify=False turns off certificate checking, so the "
                                 "connection is encrypted to whoever answers, not to "
                                 "whoever you meant")
            elif re.search(r"(?i)_create_unverified_context", callee):
                yield node, ("an unverified SSL context accepts any certificate, "
                             "including one an attacker generated a second ago")
        elif node.type in ("assignment", "expression_statement"):
            if re.search(r"ssl\._create_default_https_context\s*=\s*"
                         r"ssl\._create_unverified_context", text):
                yield node, ("the default HTTPS context is replaced with an unverified "
                             "one, disabling certificate checking process-wide")
            elif re.search(r"(?i)CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(0|False)", text):
                yield node, "libcurl certificate verification is switched off"


# ------------------------------------- CS016 cleartext transmission (Python)

# Anchored, and no internal whitespace: the whole literal has to BE a URL.
# Prose that merely contains "http://" - documentation, an explanation, an error
# message - is not a request target, and matching it made this rule fire on our
# own explanation templates.
CLEARTEXT_PY = re.compile(
    r"""^["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\{)[^"'\s]+["']$""")
SCHEMA_URL_PY = re.compile(r"(?i)(xmlns|w3\.org|schema|namespace|doctype|dtd|"
                           r"purl\.org|apache\.org/licenses)")
def match_cleartext_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "string":
            continue
        text = ps.text(node)
        if not CLEARTEXT_PY.search(text) or SCHEMA_URL_PY.search(text):
            continue
        parent = node.parent
        context = ps.text(parent) if parent is not None else ""
        # Strip the literal itself: a URL always contains "http", which would
        # otherwise make the network-call guard match everything.
        context = context.replace(text, " ")
        if not looks_like_request_target(context, context):
            continue
        yield node, ("a request target uses http://, so the traffic and anything in it - "
                     "credentials included - travels unencrypted")


# ---------------------------------- CS017 sensitive data in logs (Python)

LOG_CALL_PY = re.compile(
    r"(?i)^(print|pprint|(log|logger|logging|_log)\.(info|debug|warning|warn|error|"
    r"critical|exception))$")


def _logged_identifiers(ps: ParsedSource, args: Node | None) -> list[str]:
    """Names actually passed to the log call, ignoring string literals.

    A message that merely mentions the word "password" is not a leak; a variable
    called `password` being interpolated into it is. Matching the raw argument
    text cannot tell those apart, and the difference is most of this rule's
    false-positive rate.
    """
    if args is None:
        return []
    names: list[str] = []
    for n in walk(args):
        if n.type in ("identifier", "attribute"):
            names.append(ps.text(n))
        elif n.type == "interpolation":            # f-string {value}
            names.extend(ps.text(c) for c in n.children if c.type != "{")
    return names


def match_log_leak_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call":
            continue
        callee = _callee(ps, node).strip()
        if not LOG_CALL_PY.match(callee.rsplit(".", 1)[-1]) and \
                not LOG_CALL_PY.match(callee):
            continue
        args_node = node.child_by_field_name("arguments")
        names = _logged_identifiers(ps, args_node)
        if not any(SECRET_IN_LOG.search(n) for n in names):
            continue
        args = ps.text(args_node) if args_node is not None else ""
        if re.search(r"(?i)(redact|mask|\*{3,}|sha256|hashed)", args):
            continue
        yield node, ("a credential-named value is written to a log; log files are read "
                     "by more people and shipped to more places than the code is")


SECRET_IN_LOG = re.compile(
    r"(?i)\b\w*(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|passphrase|session[_-]?id)\w*\b")


# ---------------- extra shapes folded into classes that already exist ----------

def match_toctou_mktemp_py(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    """tempfile.mktemp() is the textbook check-then-use race: it returns a name
    that does not exist yet, and anything can create it before you do."""
    for node in walk(ps.root):
        if node.type != "call":
            continue
        if re.search(r"(?i)\btempfile\.mktemp\b|(?<![\w.])mktemp\b", _callee(ps, node)):
            yield node, ("tempfile.mktemp() returns a name, not a file - between the name "
                         "being chosen and your code creating it, anything can take it")


PYTHON_EXTENDED2: list[Rule] = [
    Rule("CS014", "Unsafe deserialization", Severity.CRITICAL,
         "CWE-502", "A08:2021 - Software and Data Integrity Failures",
         PY, match_deserialization_py),
    Rule("CS015", "Certificate validation disabled", Severity.HIGH,
         "CWE-295", "A02:2021 - Cryptographic Failures", PY, match_tls_py),
    Rule("CS016", "Cleartext transmission", Severity.MEDIUM,
         "CWE-319", "A02:2021 - Cryptographic Failures", PY, match_cleartext_py),
    Rule("CS017", "Sensitive data written to logs", Severity.MEDIUM,
         "CWE-532", "A09:2021 - Security Logging and Monitoring Failures",
         PY, match_log_leak_py, redact=True),

    # tempfile.mktemp is a second shape of the same TOCTOU race CS013 covers.
    Rule("CS013", "Check-then-use race", Severity.LOW,
         "CWE-367", "A04:2021 - Insecure Design", PY, match_toctou_mktemp_py,
         tier=Tier.ADVISORY),
]
