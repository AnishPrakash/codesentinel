"""The 52-feature vector. Order is a contract with the trained model - appending
is safe, reordering or removing is not. Bump FEATURE_VERSION if you change it.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from tree_sitter import Node

from ..models import Language as Lang
from ..parser import ParsedSource, enclosing_function, max_depth, walk

FEATURE_VERSION = 1

FEATURE_NAMES: list[str] = [
    # -- lexical / pattern (14)
    "has_aws_key_literal", "has_api_key_assign", "has_private_key_block",
    "has_password_literal", "n_high_entropy_strings", "max_string_entropy",
    "has_sql_keyword_string", "has_sql_string_concat", "has_sql_interpolation",
    "uses_eval_exec", "uses_os_command", "uses_shell_true",
    "uses_weak_hash", "uses_insecure_random",
    # -- AST structural (14)
    "n_functions", "n_classes", "max_nesting_depth", "cyclomatic_approx",
    "n_calls", "n_imports", "n_routes", "n_auth_decorators",
    "auth_route_ratio", "n_db_calls", "n_db_calls_in_auth",
    "unprotected_db_ratio", "n_try_blocks", "try_function_ratio",
    # -- naive dataflow (8)
    "n_params_in_query", "n_params_in_path", "n_params_in_command",
    "n_sanitizer_calls", "sanitizer_sink_ratio", "n_input_sources",
    "n_sinks", "n_source_sink_pairs",
    # -- naming / semantics (6)
    "n_secret_named_vars", "secret_var_ratio", "n_comments",
    "comment_density", "n_type_annotations", "annotation_ratio",
    # -- dependencies (4)
    "n_third_party_imports", "n_unknown_packages",
    "unknown_package_ratio", "has_unpinned_requirement",
    # -- metadata (6)
    "loc", "n_blank_lines", "avg_line_length", "max_line_length",
    "lang_is_python", "lang_is_javascript",
]
assert len(FEATURE_NAMES) == 52, len(FEATURE_NAMES)

# --------------------------------------------------------------- lexicons

AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
# No \b anchors: "DB_PASSWORD" must match "password", and "_" is a word
# character, so a leading \b would never fire on the most common naming style.
SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|auth[_-]?token|passphrase)"
)
SQL_KEYWORD = re.compile(
    r"(?i)\b(?:select\b.{0,120}\bfrom\b|insert\s+into\b|update\b.{0,80}\bset\b|"
    r"delete\s+from\b|drop\s+table\b|union\s+select\b)"
)

WEAK_HASH = {"md5", "sha1", "createhash"}
INSECURE_RANDOM = {"random", "randint", "randrange", "choice", "shuffle"}
EVAL_NAMES = {"eval", "exec", "execfile", "compile"}
OS_COMMAND = {"system", "popen", "spawn", "execsync", "exec", "spawnsync", "run", "call",
              "check_output", "check_call"}

AUTH_MARKERS = re.compile(
    r"(?i)(login_required|requires_auth|require_auth|authenticate|authenticated|"
    r"jwt_required|permission_required|ensure_auth|is_authenticated|current_user|"
    r"verify_token|auth_middleware|passport|requiresauth)"
)
ROUTE_MARKERS = re.compile(r"(?i)\b(route|get|post|put|patch|delete|app|router)\b")

DB_CALL = re.compile(
    r"(?i)\b(execute|executemany|raw|query|find|findone|aggregate|cursor|"
    r"session\.execute|db\.query|collection\.)\b"
)
SANITIZER = re.compile(
    r"(?i)\b(escape|sanitize|quote|parameterize|bindparam|validate|clean|"
    r"escapehtml|shlex\.quote|re\.escape)\b"
)
INPUT_SOURCE = re.compile(
    r"(?i)(request\.(args|form|json|body|query|params|values|cookies|headers)|"
    r"req\.(body|query|params)|input\(|sys\.argv|process\.argv|os\.environ\[)"
)
SINK = re.compile(
    r"(?i)(execute|eval|exec|system|popen|spawn|innerhtml|writefile|open\(|"
    r"send_file|render_template_string|subprocess)"
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _safe_ratio(num: float, den: float) -> float:
    return num / den if den else 0.0


# --------------------------------------------------------------- extractor

class FeatureExtractor:
    """Computes the fixed 52-vector for one parsed source."""

    def __init__(self, known_packages: set[str] | None = None) -> None:
        self.known = known_packages or set()

    def extract(self, ps: ParsedSource) -> list[float]:
        f: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
        code = ps.code
        lines = code.splitlines()
        is_py = ps.language is Lang.PYTHON

        # ---------- collect nodes once ----------
        strings, calls, funcs, classes, imports = [], [], [], [], []
        comments, decorators, tries, annotations, assigns = [], [], [], [], []

        for n in walk(ps.root):
            t = n.type
            if t in ("string", "string_literal", "template_string", "concatenated_string"):
                strings.append(n)
            elif t == "call" or t == "call_expression":
                calls.append(n)
            elif t in ("function_definition", "function_declaration",
                       "function_expression", "arrow_function", "method_definition"):
                funcs.append(n)
            elif t in ("class_definition", "class_declaration"):
                classes.append(n)
            elif t in ("import_statement", "import_from_statement",
                       "lexical_declaration", "variable_declaration"):
                if t.startswith("import") or "require(" in ps.text(n):
                    imports.append(n)
            elif t == "comment":
                comments.append(n)
            elif t == "decorator":
                decorators.append(n)
            elif t in ("try_statement",):
                tries.append(n)
            elif t == "type" or t == "type_annotation":
                annotations.append(n)
            elif t in ("assignment", "augmented_assignment", "variable_declarator"):
                assigns.append(n)

        string_texts = [ps.text(s) for s in strings]
        assign_texts = [ps.text(a) for a in assigns]

        # ---------- group 1: lexical / pattern (14) ----------
        f["has_aws_key_literal"] = float(bool(AWS_KEY.search(code)))
        f["has_private_key_block"] = float(bool(PRIVATE_KEY.search(code)))

        secret_assigns = [a for a in assign_texts if SECRET_NAME.search(a)]
        literal_secret = [
            a for a in secret_assigns
            if re.search(r"""=\s*["'][^"']{6,}["']""", a)
        ]
        f["has_api_key_assign"] = float(any(
            re.search(r"(?i)(api[_-]?key|token|secret)", a) for a in literal_secret))
        f["has_password_literal"] = float(any(
            re.search(r"(?i)pass(word|wd)?", a) for a in literal_secret))

        entropies = [shannon(t.strip("\"'`")) for t in string_texts if len(t) > 12]
        f["n_high_entropy_strings"] = float(sum(1 for e in entropies if e > 4.0))
        f["max_string_entropy"] = float(max(entropies) if entropies else 0.0)

        f["has_sql_keyword_string"] = float(any(SQL_KEYWORD.search(t) for t in string_texts))
        f["has_sql_string_concat"] = float(any(
            SQL_KEYWORD.search(ps.text(n)) and self._has_concat(ps, n)
            for n in walk(ps.root)
            if n.type in ("binary_operator", "binary_expression")
        ))
        f["has_sql_interpolation"] = float(any(
            SQL_KEYWORD.search(t) and (
                "{" in t or "${" in t or "%s" in t or "' +" in t or '" +' in t)
            for t in string_texts
        ))

        f["uses_eval_exec"] = float(any(
            self._callee_name(ps, c) in EVAL_NAMES for c in calls))
        f["uses_os_command"] = float(any(
            self._callee_name(ps, c) in OS_COMMAND for c in calls))
        f["uses_shell_true"] = float(bool(re.search(r"shell\s*=\s*True", code)))
        f["uses_weak_hash"] = float(any(
            self._callee_name(ps, c) in WEAK_HASH or
            re.search(r"(?i)\b(md5|sha1)\b", ps.text(c)) for c in calls))
        f["uses_insecure_random"] = float(
            bool(re.search(r"(?i)\b(random\.(random|randint|choice|shuffle)|Math\.random)\b",
                           code))
        )

        # ---------- group 2: AST structural (14) ----------
        f["n_functions"] = float(len(funcs))
        f["n_classes"] = float(len(classes))
        f["max_nesting_depth"] = float(max_depth(ps.root))

        branch_types = {"if_statement", "for_statement", "while_statement",
                        "conditional_expression", "except_clause", "case_clause"}
        f["cyclomatic_approx"] = float(
            1 + sum(1 for n in walk(ps.root) if n.type in branch_types))
        f["n_calls"] = float(len(calls))
        f["n_imports"] = float(len(imports))

        routes = self._route_nodes(ps, decorators, calls, is_py)
        f["n_routes"] = float(len(routes))

        auth_decorators = [d for d in decorators if AUTH_MARKERS.search(ps.text(d))]
        f["n_auth_decorators"] = float(len(auth_decorators))
        f["auth_route_ratio"] = _safe_ratio(len(auth_decorators), len(routes))

        db_calls = [c for c in calls if DB_CALL.search(ps.text(c))]
        f["n_db_calls"] = float(len(db_calls))
        protected = sum(1 for c in db_calls if self._is_authenticated(ps, c))
        f["n_db_calls_in_auth"] = float(protected)
        f["unprotected_db_ratio"] = _safe_ratio(len(db_calls) - protected, len(db_calls))

        f["n_try_blocks"] = float(len(tries))
        f["try_function_ratio"] = _safe_ratio(len(tries), len(funcs))

        # ---------- group 3: naive dataflow (8) ----------
        sources = [c for c in calls if INPUT_SOURCE.search(ps.text(c))]
        sources += [n for n in walk(ps.root)
                    if n.type in ("attribute", "member_expression")
                    and INPUT_SOURCE.search(ps.text(n))]
        sinks = [c for c in calls if SINK.search(ps.text(c))]
        sanitizers = [c for c in calls if SANITIZER.search(ps.text(c))]

        f["n_input_sources"] = float(len(sources))
        f["n_sinks"] = float(len(sinks))
        f["n_sanitizer_calls"] = float(len(sanitizers))
        f["sanitizer_sink_ratio"] = _safe_ratio(len(sanitizers), len(sinks))
        f["n_source_sink_pairs"] = float(self._source_sink_pairs(ps, sources, sinks))

        f["n_params_in_query"] = float(sum(
            1 for c in db_calls if self._mentions_param(ps, c)))
        f["n_params_in_path"] = float(sum(
            1 for c in calls
            if re.search(r"(?i)\b(open|readfile|writefile|join|send_file)\b", ps.text(c))
            and self._mentions_param(ps, c)))
        f["n_params_in_command"] = float(sum(
            1 for c in calls
            if self._callee_name(ps, c) in OS_COMMAND and self._mentions_param(ps, c)))

        # ---------- group 4: naming / semantics (6) ----------
        secret_vars = [a for a in assign_texts if SECRET_NAME.search(a.split("=")[0])]
        f["n_secret_named_vars"] = float(len(secret_vars))
        f["secret_var_ratio"] = _safe_ratio(len(secret_vars), len(assign_texts))
        f["n_comments"] = float(len(comments))
        f["comment_density"] = _safe_ratio(len(comments), max(len(lines), 1))
        f["n_type_annotations"] = float(len(annotations))
        f["annotation_ratio"] = _safe_ratio(len(annotations), len(funcs))

        # ---------- group 5: dependencies (4) ----------
        pkgs = self._imported_packages(ps, imports)
        third_party = [p for p in pkgs if not self._is_stdlib(p, is_py)]
        unknown = [p for p in third_party if self.known and p.lower() not in self.known]
        f["n_third_party_imports"] = float(len(third_party))
        f["n_unknown_packages"] = float(len(unknown))
        f["unknown_package_ratio"] = _safe_ratio(len(unknown), len(third_party))
        f["has_unpinned_requirement"] = float(
            bool(re.search(r"(?m)^\s*[A-Za-z0-9_.-]+\s*$", code))
            and "requirements" in ps.code[:80].lower()
        )

        # ---------- group 6: metadata (6) ----------
        f["loc"] = float(len(lines))
        f["n_blank_lines"] = float(sum(1 for ln in lines if not ln.strip()))
        lengths = [len(ln) for ln in lines] or [0]
        f["avg_line_length"] = float(sum(lengths) / len(lengths))
        f["max_line_length"] = float(max(lengths))
        f["lang_is_python"] = float(is_py)
        f["lang_is_javascript"] = float(not is_py)

        return [f[name] for name in FEATURE_NAMES]

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _callee_name(ps: ParsedSource, call: Node) -> str:
        fn = call.child_by_field_name("function")
        if fn is None:
            return ""
        text = ps.text(fn)
        return text.rsplit(".", 1)[-1].strip().lower()

    @staticmethod
    def _has_concat(ps: ParsedSource, node: Node) -> bool:
        op = ps.text(node)
        return "+" in op and ('"' in op or "'" in op)

    @staticmethod
    def _route_nodes(ps: ParsedSource, decorators, calls, is_py: bool) -> list[Node]:
        if is_py:
            return [d for d in decorators
                    if re.search(r"(?i)@\w*(app|router|bp|blueprint)\.\w+", ps.text(d))]
        return [c for c in calls
                if re.match(r"(?i)^(app|router)\.(get|post|put|patch|delete|use)\(",
                            ps.text(c).strip())]

    @staticmethod
    def _is_authenticated(ps: ParsedSource, node: Node) -> bool:
        """Walk up to the enclosing function and check its decorators/body for an
        auth marker. This is the relational check CS005 is built on."""
        fn = enclosing_function(node)
        if fn is None:
            return False
        parent = fn.parent
        scope = ps.text(parent) if parent is not None else ps.text(fn)
        head = scope[: scope.find("{") + 1] if "{" in scope else scope[:400]
        return bool(AUTH_MARKERS.search(head))

    @staticmethod
    def _mentions_param(ps: ParsedSource, call: Node) -> bool:
        fn = enclosing_function(call)
        if fn is None:
            return False
        params = fn.child_by_field_name("parameters")
        if params is None:
            return False
        names = {w for w in re.findall(r"[A-Za-z_]\w*", ps.text(params))}
        used = set(re.findall(r"[A-Za-z_]\w*", ps.text(call)))
        return bool(names & used - {"self", "req", "res", "next"})

    @staticmethod
    def _source_sink_pairs(ps: ParsedSource, sources, sinks) -> int:
        """Count functions containing both a user-input source and a dangerous sink.
        Deliberately naive - this is a feature for the model, not a finding."""
        src_fns = {id(enclosing_function(s)) for s in sources} - {id(None)}
        sink_fns = {id(enclosing_function(s)) for s in sinks} - {id(None)}
        return len(src_fns & sink_fns)

    @staticmethod
    def _imported_packages(ps: ParsedSource, imports) -> list[str]:
        pkgs: list[str] = []
        for node in imports:
            text = ps.text(node)
            for m in re.finditer(r"(?:^|\s)(?:import|from)\s+([A-Za-z_][\w.]*)", text):
                pkgs.append(m.group(1).split(".")[0])
            for m in re.finditer(r"""require\(\s*["']([^"'/]+)""", text):
                pkgs.append(m.group(1))
            for m in re.finditer(r"""from\s+["']([^"'/]+)""", text):
                pkgs.append(m.group(1))
        return [p for p in pkgs if p]

    @staticmethod
    def _is_stdlib(pkg: str, is_py: bool) -> bool:
        import sys
        if is_py:
            return pkg in sys.stdlib_module_names
        return pkg in {"fs", "path", "http", "https", "crypto", "os", "util",
                       "events", "stream", "child_process", "url", "zlib"}


def extract_features(ps: ParsedSource, known_packages: set[str] | None = None) -> list[float]:
    return FeatureExtractor(known_packages).extract(ps)
