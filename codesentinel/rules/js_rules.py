"""JavaScript equivalents. Same ids, same CWEs - only the syntax differs."""
from __future__ import annotations

import re
from typing import Iterator

from tree_sitter import Node

from ..models import Language, Severity
from ..parser import ParsedSource, walk
from .base import Rule
from .python_rules import AWS_KEY, GENERIC_KEY, PRIVATE_KEY, SECRET_NAME, SQL

JS = frozenset({Language.JAVASCRIPT})

JS_AUTH = re.compile(
    r"(?i)(requireauth|isauthenticated|authenticate|passport\.|jwt|verifytoken|"
    r"ensureloggedin|authmiddleware|req\.user)"
)
JS_ROUTE = re.compile(r"(?i)^\s*(app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(")
JS_DB = re.compile(r"(?i)\b(query|execute|findone|find|aggregate|raw)\s*\(")


def match_secret_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("variable_declarator", "assignment_expression", "pair"):
            continue
        text = ps.text(node)
        if AWS_KEY.search(text):
            yield node, "an AWS access key id written directly into the source"
        elif GENERIC_KEY.search(text):
            yield node, "a provider API token written directly into the source"
        elif PRIVATE_KEY.search(text):
            yield node, "a PEM private key block embedded in the source"
        elif SECRET_NAME.search(text.split("=")[0]) and re.search(
                r"""=\s*["'`][^"'`]{6,}["'`]""", text):
            if not re.search(r"(?i)(process\.env|config\.|import\.meta\.env)", text):
                yield node, "a credential-named variable holds a literal value"


def match_sql_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node)
        if not JS_DB.search(text) or not SQL.search(text):
            continue
        if "`" in text and "${" in text:
            yield node, "the query is built with a template literal interpolating a variable"
        elif re.search(r'["\']\s*\+|\+\s*["\']', text):
            yield node, "the query is built by concatenating a string with a variable"


def match_command_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node)
        if re.search(r"(?i)\b(child_process\.)?(exec|execSync)\s*\(", text):
            if "${" in text or re.search(r'["\']\s*\+', text):
                yield node, "a shell command is assembled from a variable and executed"
        elif re.search(r"(?i)\beval\s*\(", text):
            yield (node, "eval() executes a constructed string as code",
                   "CWE-95", "A03:2021 - Injection")


def match_weak_crypto_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node)
        m = re.search(r"""createHash\s*\(\s*["'](md5|sha1)["']""", text, re.I)
        if m:
            yield node, f"{m.group(1).upper()} is used, which is broken for any security purpose"
        elif re.search(r"\bMath\.random\s*\(", text) and SECRET_NAME.search(ps.code):
            yield (node, ("Math.random() is used where a value looks security-relevant; "
                          "it is predictable and not cryptographically secure"),
                   "CWE-338", "A02:2021 - Cryptographic Failures")


def match_missing_auth_js(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "call_expression":
            continue
        text = ps.text(node)
        if not JS_ROUTE.match(text.strip()):
            continue
        if JS_AUTH.search(text):
            continue
        if not JS_DB.search(text):
            continue
        if not re.search(r"req\.(params|query|body)", text):
            continue
        yield node, ("this route reads data using a value from req.params/query/body and has "
                     "no authentication middleware and no auth check in its handler")


JS_RULES: list[Rule] = [
    Rule("CS001", "Hardcoded credential in source", Severity.CRITICAL,
         "CWE-798", "A07:2021 - Identification and Authentication Failures",
         JS, match_secret_js, redact=True),
    Rule("CS002", "SQL query built by string construction", Severity.CRITICAL,
         "CWE-89", "A03:2021 - Injection", JS, match_sql_js),
    Rule("CS003", "Shell command built from untrusted input", Severity.CRITICAL,
         "CWE-78", "A03:2021 - Injection", JS, match_command_js),
    Rule("CS004", "Broken or unsuitable cryptography", Severity.MEDIUM,
         "CWE-327", "A02:2021 - Cryptographic Failures", JS, match_weak_crypto_js),
    Rule("CS005", "Route reads data with no authentication", Severity.CRITICAL,
         "CWE-306", "A01:2021 - Broken Access Control", JS, match_missing_auth_js),
]
