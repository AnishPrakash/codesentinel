"""Rule classes for Python. Each matcher is a pure function over the tree."""
from __future__ import annotations

import re
from typing import Iterator

from tree_sitter import Node

from ..models import Language, Severity
from ..parser import ParsedSource, enclosing_function, walk
from .base import Rule

PY = frozenset({Language.PYTHON})

AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GCP_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
GENERIC_KEY = re.compile(
    r"\b(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|gh[opsu]_[A-Za-z0-9]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z\-_]{35})\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)"
)
SQL = re.compile(
    r"(?i)\b(?:select\b.{0,120}\bfrom\b|insert\s+into\b|update\b.{0,80}\bset\b|"
    r"delete\s+from\b|drop\s+table\b)"
)
AUTH = re.compile(
    r"(?i)(login_required|requires?_auth|authenticated|jwt_required|permission_required|"
    r"current_user|verify_token|require_login|auth_required)"
)
WEAK_HASH_CALL = re.compile(r"(?i)\b(hashlib\.)?(md5|sha1)\s*\(")
DB_EXEC = re.compile(r"(?i)\b(execute|executemany|raw|execute_sql)\s*\(")
ROUTE_DEC = re.compile(
    r"(?i)@\s*\w*(app|router|bp|blueprint)\s*\.\s*(route|get|post|put|patch|delete)")


def _callee(ps: ParsedSource, call: Node) -> str:
    fn = call.child_by_field_name("function")
    return ps.text(fn) if fn is not None else ""


# ------------------------------------------------------------ CS001 secrets

COMMENTED_CREDENTIAL = re.compile(
    r"""(?im)^\s*#\s*\w*(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key)\w*"""
    r"""\s*=\s*["'][^"']{4,}["']""")


def match_hardcoded_secret(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    # A credential does not stop being a credential because it was commented out.
    # git keeps it, and so does anyone who cloned the repo.
    for node in walk(ps.root):
        if node.type == "comment" and COMMENTED_CREDENTIAL.search(ps.text(node)):
            yield node, ("a credential is present in a commented-out line - commenting "
                         "it out removes it from execution, not from the file or its "
                         "history")

    for node in walk(ps.root):
        if node.type != "assignment":
            continue
        text = ps.text(node)
        left = text.split("=", 1)[0]
        right = text.split("=", 1)[1] if "=" in text else ""

        if AWS_KEY.search(text):
            yield node, "an AWS access key id (AKIA...) written directly into the source"
            continue
        if GENERIC_KEY.search(text):
            yield node, "a provider API token written directly into the source"
            continue
        if PRIVATE_KEY.search(text):
            yield node, "a PEM private key block embedded in the source"
            continue
        # a secret-sounding name assigned a non-trivial string literal
        if SECRET_NAME.search(left) and re.search(r"""^\s*["'][^"']{6,}["']\s*$""", right):
            if not re.search(r"(?i)(os\.environ|getenv|config\[|settings\.)", right):
                yield node, f"the variable {left.strip()!r} holds a literal credential"


# --------------------------------------------------------- CS002 SQL injection

def match_sql_injection(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("call",):
            continue
        if not DB_EXEC.search(_callee(ps, node) + "("):
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_text = ps.text(args)
        if not SQL.search(arg_text):
            continue
        # concatenation, %-format, .format(), or an f-string all splice user data
        if re.search(r'["\']\s*\+', arg_text) or re.search(r'\+\s*["\']', arg_text):
            yield node, "the query is built by concatenating a string with a variable"
        elif re.search(r"""f["']""", arg_text) and "{" in arg_text:
            yield node, "the query is built with an f-string interpolating a variable"
        elif ".format(" in arg_text or re.search(r"""%\s*\(?\w""", arg_text):
            yield node, "the query is built with string formatting rather than bound parameters"


# ------------------------------------------------------ CS003 command injection

def match_command_injection(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call":
            continue
        callee = _callee(ps, node)
        args = node.child_by_field_name("arguments")
        arg_text = ps.text(args) if args is not None else ""

        if re.search(r"(?i)\b(os\.system|os\.popen)\b", callee):
            if re.search(r"[+%]|\.format\(|f[\"']", arg_text):
                yield node, "a shell command is assembled from a variable and executed"
        elif re.search(r"(?i)subprocess\.(run|call|Popen|check_output|check_call)", callee):
            if re.search(r"shell\s*=\s*True", arg_text):
                yield node, ("subprocess is invoked with shell=True, so the argument is "
                             "parsed by a shell")
        elif re.fullmatch(r"\s*(eval|exec)\s*", callee):
            yield node, f"{callee.strip()}() executes a constructed string as code"


# ------------------------------------------------------------- CS004 weak crypto

WEAK_CIPHER = re.compile(r"(?i)\b(DES|TripleDES|DES3|ARC[24]|RC[24]|Blowfish|IDEA|CAST5)\b")
ECB_MODE = re.compile(r"(?i)\bMODE_ECB\b|modes\.ECB\b")


def match_weak_crypto(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call":
            continue
        callee = _callee(ps, node)
        text = ps.text(node)
        if WEAK_HASH_CALL.search(callee + "("):
            algo = "MD5" if re.search(r"(?i)md5", callee) else "SHA-1"
            yield node, f"{algo} is used, which is broken for any security purpose"
        elif WEAK_CIPHER.search(callee) and re.search(r"(?i)\b(new|Cipher|encrypt)\b", text):
            algo = WEAK_CIPHER.search(callee).group(1).upper()
            yield node, (f"{algo} is used; it is a deprecated cipher with a key or block "
                         "size too small to be safe today")
        elif ECB_MODE.search(text):
            yield node, ("ECB mode encrypts identical plaintext blocks to identical "
                         "ciphertext blocks, so the structure of the data survives "
                         "encryption")
        elif re.search(r"(?i)\brandom\.(random|randint|choice|shuffle|randrange)\b", callee):
            enclosing = ps.text(enclosing_function(node) or node)
            if SECRET_NAME.search(enclosing):
                yield node, ("the `random` module is used where a value looks "
                             "security-relevant; it is predictable and not "
                             "cryptographically secure")


# --------------------------------------------------------- CS005 missing auth
#
# The relational rule. Everything above is a pattern; this one is a graph query.

def match_missing_auth(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "decorated_definition":
            continue
        decorators = [ps.text(d) for d in node.children if d.type == "decorator"]
        if not any(ROUTE_DEC.search(d) for d in decorators):
            continue
        if any(AUTH.search(d) for d in decorators):
            continue

        body = node.child_by_field_name("definition") or node
        body_text = ps.text(body)
        if AUTH.search(body_text):
            continue                      # auth checked inside the handler

        # does it actually touch data? a route that returns a constant is not a finding
        touches_data = bool(DB_EXEC.search(body_text)) or bool(
            re.search(r"(?i)\b(query|filter|get_or_404|find_one|objects\.)\b", body_text))
        if not touches_data:
            continue

        # does it take a client-controlled identifier?
        takes_param = bool(re.search(r"<\w*:?\w+>", " ".join(decorators))) or bool(
            re.search(r"(?i)request\.(args|json|form|values)", body_text))
        if not takes_param:
            continue

        route = next((d for d in decorators if ROUTE_DEC.search(d)), "this route")
        yield node, (f"{route.strip()} reads data using a client-supplied value and has no "
                     "authentication decorator, and no authentication check in its body")


# ------------------------------------------------- CS006 unknown dependency
# Implemented in deps/firewall.py; registered there so the ids stay in one place.


PYTHON_RULES: list[Rule] = [
    Rule("CS001", "Hardcoded credential in source", Severity.CRITICAL,
         "CWE-798", "A07:2021 - Identification and Authentication Failures",
         PY, match_hardcoded_secret, redact=True),
    Rule("CS002", "SQL query built by string construction", Severity.CRITICAL,
         "CWE-89", "A03:2021 - Injection", PY, match_sql_injection),
    Rule("CS003", "Shell command built from untrusted input", Severity.CRITICAL,
         "CWE-78", "A03:2021 - Injection", PY, match_command_injection),
    Rule("CS004", "Broken or unsuitable cryptography", Severity.MEDIUM,
         "CWE-327", "A02:2021 - Cryptographic Failures", PY, match_weak_crypto),
    Rule("CS005", "Route reads data with no authentication", Severity.CRITICAL,
         "CWE-306", "A01:2021 - Broken Access Control", PY, match_missing_auth),
]
