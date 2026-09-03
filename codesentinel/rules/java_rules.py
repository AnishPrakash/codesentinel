"""Java rules. Same ids, same CWEs, different syntax.

Java coverage is deliberately a subset. CS006 (dependency provenance) is absent
because Java resolves dependencies through Maven and Gradle coordinates, not
import names, so an import-name manifest would say nothing useful - and saying
nothing beats guessing. `cs rules --lang java` prints exactly what is covered.
"""
from __future__ import annotations

import re
from typing import Iterator

from tree_sitter import Node

from ..models import Language, Severity
from ..parser import ParsedSource, enclosing_function, walk
from .base import Rule, looks_like_request_target

JAVA = frozenset({Language.JAVA})

J_SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|passphrase)")
J_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
J_GCP_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
J_SQL = re.compile(
    r"(?i)\b(?:select\b.{0,120}\bfrom\b|insert\s+into\b|update\b.{0,80}\bset\b|"
    r"delete\s+from\b|drop\s+table\b)")
J_DB_EXEC = re.compile(r"(?i)\b(executeQuery|executeUpdate|execute|createQuery|"
                       r"prepareStatement|nativeQuery)\b")
J_ROUTE = re.compile(
    r"(?i)@\s*(Get|Post|Put|Patch|Delete|Request)Mapping\b|@\s*Path\b|"
    r"@\s*(GET|POST|PUT|DELETE)\b")
J_AUTH = re.compile(
    r"(?i)(PreAuthorize|PostAuthorize|Secured|RolesAllowed|DenyAll|"
    r"SecurityContextHolder|getPrincipal|isUserInRole|Authentication\b|"
    r"@\s*Authenticated)")
J_PARAM = re.compile(r"(?i)@\s*(PathVariable|RequestParam|RequestBody|QueryParam|"
                     r"PathParam|FormParam)\b")


def _name(ps: ParsedSource, call: Node) -> str:
    """method_invocation -> object.name; object_creation_expression -> type."""
    obj = call.child_by_field_name("object")
    nm = call.child_by_field_name("name") or call.child_by_field_name("type")
    parts = [ps.text(n) for n in (obj, nm) if n is not None]
    return ".".join(parts)


def _args(ps: ParsedSource, call: Node) -> str:
    a = call.child_by_field_name("arguments")
    return ps.text(a) if a is not None else ""


def _enclosing_method(ps: ParsedSource, node: Node) -> str:
    fn = enclosing_function(node)
    return ps.text(fn) if fn is not None else ""


# ------------------------------------------------------------ CS001 secrets

def match_secret_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("field_declaration", "local_variable_declaration"):
            continue
        text = ps.text(node)
        if J_AWS_KEY.search(text):
            yield node, "an AWS access key id written directly into the source"
            continue
        if J_GCP_KEY.search(text):
            yield node, "a Google API key written directly into the source"
            continue
        if not J_SECRET_NAME.search(text.split("=")[0]):
            continue
        if not re.search(r"""=\s*"[^"]{6,}"\s*;?""", text):
            continue
        if re.search(r"(?i)(System\.getenv|getProperty|@Value|Environment\.)", text):
            continue
        yield node, "a credential-named field holds a literal String value"


# --------------------------------------------------------- CS002 SQL injection

def match_sql_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "method_invocation":
            continue
        if not J_DB_EXEC.search(_name(ps, node)):
            continue
        args = _args(ps, node)
        if not J_SQL.search(args):
            continue
        if re.search(r'"\s*\+|\+\s*"', args):
            yield node, ("the query is built by concatenating a String with a variable, "
                         "so a PreparedStatement is not protecting it")
        elif re.search(r"String\.format|concat\(|StringBuilder", args):
            yield node, "the query is built with String formatting rather than bound parameters"


# ------------------------------------------------------ CS003 command injection

def match_command_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("method_invocation", "object_creation_expression"):
            continue
        callee = _name(ps, node)
        args = _args(ps, node)
        if re.search(r"(?i)\bexec\b", callee) and "Runtime" in ps.text(node):
            if re.search(r'"\s*\+|\+\s*"|String\.format', args):
                yield node, ("a shell command is assembled from a variable and handed to "
                             "Runtime.exec")
        elif re.search(r"(?i)ProcessBuilder", callee):
            if re.search(r'"\s*\+|\+\s*"', args) and re.search(r"(?i)(sh|cmd|bash)", args):
                yield node, ("a ProcessBuilder command line is assembled from a variable "
                             "and passed through a shell")


# ------------------------------------------------------------- CS004 weak crypto

WEAK_ALGO = re.compile(r"""(?i)["'](MD5|MD2|SHA-?1|DES|DESede|RC2|RC4|Blowfish)\b""")
ECB_MODE = re.compile(r"""(?i)["'][A-Z0-9]+/ECB/""")


def match_weak_crypto_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("method_invocation", "object_creation_expression"):
            continue
        text = ps.text(node)
        callee = _name(ps, node)
        if re.search(r"(?i)(MessageDigest|Cipher|KeyGenerator|Mac)\.getInstance", text) \
                or re.search(r"(?i)getInstance", callee):
            m = WEAK_ALGO.search(_args(ps, node))
            if m:
                yield node, (f"{m.group(1).upper()} is requested, which is broken or "
                             "deprecated for any security purpose")
                continue
            if ECB_MODE.search(_args(ps, node)):
                yield node, ("ECB mode is requested; it encrypts identical blocks to "
                             "identical ciphertext, so structure in the plaintext survives")
                continue
        if re.search(r"(?i)^new Random$|\bRandom$", callee.strip()) or \
                re.search(r"\bnew\s+Random\s*\(", text):
            if J_SECRET_NAME.search(_enclosing_method(ps, node)):
                yield node, ("java.util.Random is used where a value looks "
                             "security-relevant; use SecureRandom, which is not predictable")


# --------------------------------------------------------- CS005 missing auth

def match_missing_auth_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "method_declaration":
            continue
        text = ps.text(node)
        annotations = [ps.text(c) for c in node.children
                       if c.type in ("modifiers",)]
        head = " ".join(annotations)
        if not J_ROUTE.search(head):
            continue
        if J_AUTH.search(text):
            continue
        if not J_DB_EXEC.search(text) and not re.search(
                r"(?i)\b(findBy|findOne|getOne|repository\.|entityManager\.)", text):
            continue
        if not J_PARAM.search(text):
            continue
        yield node, ("this handler reads data using a client-supplied path or query "
                     "parameter and carries no @PreAuthorize, @Secured or @RolesAllowed, "
                     "and checks no principal in its body")


# ------------------------------------------------------ CS008 path traversal

J_FILE_SINK = re.compile(r"(?i)\b(new File|Files\.(readAllBytes|readString|newInputStream|"
                         r"copy|delete)|FileInputStream|FileReader|Paths\.get)\b")
J_SANITISER = re.compile(r"(?i)\b(getFileName|normalize|toRealPath|startsWith|"
                         r"FilenameUtils\.getName|replaceAll)\b")


def match_path_traversal_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("method_invocation", "object_creation_expression"):
            continue
        text = ps.text(node)
        if not J_FILE_SINK.search(text):
            continue
        scope = _enclosing_method(ps, node)
        if not J_PARAM.search(scope):
            continue
        if J_SANITISER.search(scope):
            continue
        yield node, ("a file path is built from a request parameter with no normalisation, "
                     "so ../ sequences resolve outside the intended directory")


# --------------------------------------------- CS014 insecure deserialization

def match_deserialization_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type not in ("method_invocation", "object_creation_expression"):
            continue
        text = ps.text(node)
        if re.search(r"\bObjectInputStream\b", text) and "new " in text:
            yield node, ("an ObjectInputStream is constructed; readObject on untrusted "
                         "bytes instantiates whatever classes the stream names")
        elif re.search(r"\bXMLDecoder\b", text) and "new " in text:
            yield node, "XMLDecoder executes the object graph described by the XML it reads"
        elif re.search(r"(?i)\bnew\s+Yaml\s*\(\s*\)", text):
            yield node, ("SnakeYAML is constructed without a SafeConstructor, so the "
                         "document can name arbitrary Java classes to instantiate")


# ---------------------------------------- CS015 certificate validation disabled

def match_tls_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    code = ps.code
    for node in walk(ps.root):
        text = ps.text(node)
        if node.type == "method_invocation":
            if re.search(r"setHostnameVerifier|setDefaultHostnameVerifier", text) and \
                    re.search(r"(?i)(ALLOW_ALL|return\s+true)", text + code[:0] or text):
                yield node, "hostname verification is replaced with one that accepts any host"
            elif re.search(r"NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER", text):
                yield node, "hostname verification is disabled"
        elif node.type == "method_declaration":
            if re.search(r"checkServerTrusted|checkClientTrusted", text) and \
                    not re.search(r"throw\s+new", text):
                yield node, ("a TrustManager accepts every certificate - its "
                             "checkServerTrusted does nothing and throws nothing")


# ------------------------------------------------- CS016 cleartext transmission

CLEARTEXT = re.compile(
    r"""^["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'\s]+["']$""")
SCHEMA_URL = re.compile(r"(?i)(xmlns|schemaLocation|w3\.org|namespace|doctype|dtd|"
                        r"apache\.org/(licenses|xml)|maven\.apache\.org)")


def match_cleartext_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "string_literal":
            continue
        text = ps.text(node)
        if not CLEARTEXT.search(text) or SCHEMA_URL.search(text):
            continue
        parent = node.parent
        context = ps.text(parent) if parent is not None else ""
        context = context.replace(text, " ")
        if not looks_like_request_target(context, context):
            continue
        yield node, ("a request target uses http://, so the traffic and anything in it "
                     "travels unencrypted")


# ------------------------------------------------ CS017 sensitive data in logs

LOG_CALL = re.compile(r"(?i)\b(System\.out\.print(ln)?|System\.err\.print(ln)?|"
                      r"(log|logger|LOG|LOGGER)\.(info|debug|warn|error|trace)|"
                      r"printStackTrace)\b")


def match_log_leak_java(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        if node.type != "method_invocation":
            continue
        text = ps.text(node)
        if not LOG_CALL.search(text):
            continue
        args_node = node.child_by_field_name("arguments")
        names = [ps.text(n) for n in (walk(args_node) if args_node is not None else [])
                 if n.type in ("identifier", "field_access")]
        if not any(J_SECRET_NAME.search(n) for n in names):
            continue
        yield node, ("a credential-named value is written to a log; log files are "
                     "read by more people and shipped to more places than the code is")


JAVA_RULES: list[Rule] = [
    Rule("CS001", "Hardcoded credential in source", Severity.CRITICAL,
         "CWE-798", "A07:2021 - Identification and Authentication Failures",
         JAVA, match_secret_java, redact=True),
    Rule("CS002", "SQL query built by string construction", Severity.CRITICAL,
         "CWE-89", "A03:2021 - Injection", JAVA, match_sql_java),
    Rule("CS003", "Shell command built from untrusted input", Severity.CRITICAL,
         "CWE-78", "A03:2021 - Injection", JAVA, match_command_java),
    Rule("CS004", "Broken or unsuitable cryptography", Severity.MEDIUM,
         "CWE-327", "A02:2021 - Cryptographic Failures", JAVA, match_weak_crypto_java),
    Rule("CS005", "Route reads data with no authentication", Severity.CRITICAL,
         "CWE-306", "A01:2021 - Broken Access Control", JAVA, match_missing_auth_java),
    Rule("CS008", "Path built from user input", Severity.HIGH,
         "CWE-22", "A01:2021 - Broken Access Control", JAVA, match_path_traversal_java),
    Rule("CS014", "Unsafe deserialization", Severity.CRITICAL,
         "CWE-502", "A08:2021 - Software and Data Integrity Failures",
         JAVA, match_deserialization_java),
    Rule("CS015", "Certificate validation disabled", Severity.HIGH,
         "CWE-295", "A02:2021 - Cryptographic Failures", JAVA, match_tls_java),
    Rule("CS016", "Cleartext transmission", Severity.MEDIUM,
         "CWE-319", "A02:2021 - Cryptographic Failures", JAVA, match_cleartext_java),
    Rule("CS017", "Sensitive data written to logs", Severity.MEDIUM,
         "CWE-532", "A09:2021 - Security Logging and Monitoring Failures",
         JAVA, match_log_leak_java),
]
