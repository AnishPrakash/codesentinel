"""CS006 - dependency provenance. Flags imports absent from the offline manifest."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterator

from tree_sitter import Node

from ..models import Finding, Language, Severity
from ..parser import ParsedSource, walk
from .manifest import known_packages

JS_STDLIB = {"fs", "path", "http", "https", "crypto", "os", "util", "events",
             "stream", "child_process", "url", "zlib", "buffer", "assert", "net"}


def _imports(ps: ParsedSource) -> Iterator[tuple[Node, str]]:
    for node in walk(ps.root):
        text = ps.text(node)
        if ps.language is Language.PYTHON:
            if node.type == "import_statement":
                for m in re.finditer(r"import\s+([A-Za-z_][\w.]*)", text):
                    yield node, m.group(1).split(".")[0]
            elif node.type == "import_from_statement":
                m = re.match(r"from\s+([A-Za-z_][\w.]*)", text)
                if m:
                    yield node, m.group(1).split(".")[0]
        else:
            if node.type == "call_expression" and text.startswith("require("):
                m = re.search(r"""require\(\s*["']([^"']+)""", text)
                if m and not m.group(1).startswith("."):
                    yield node, m.group(1).split("/")[0]
            elif node.type == "import_statement":
                m = re.search(r"""from\s+["']([^"']+)""", text)
                if m and not m.group(1).startswith("."):
                    yield node, m.group(1).split("/")[0]


def _is_stdlib(pkg: str, language: Language) -> bool:
    if language is Language.PYTHON:
        return pkg in sys.stdlib_module_names
    return pkg in JS_STDLIB


def _variants(name: str) -> set[str]:
    """PyPI and npm both treat _ and - as interchangeable in practice; the import
    name and the distribution name often differ by exactly that character."""
    low = name.lower()
    return {low, low.replace("_", "-"), low.replace("-", "_")}


def _is_local_module(pkg: str, local_root: Path | None) -> bool:
    """A module that sits beside the file being scanned is the user's own code,
    not a dependency. Without this, every `from db import session` in a project
    reads as an unrecognised package."""
    if local_root is None:
        return False
    for parent in (local_root, local_root.parent):
        try:
            if (parent / f"{pkg}.py").exists() or (parent / pkg / "__init__.py").exists():
                return True
            if (parent / f"{pkg}.js").exists() or (parent / f"{pkg}.ts").exists():
                return True
        except OSError:
            return False
    return False


def scan_dependencies(ps: ParsedSource,
                      local_root: Path | None = None) -> list[Finding]:
    manifest = known_packages(ps.language)
    if not manifest:
        return []                      # no manifest -> say nothing rather than guess

    seen: set[str] = set()
    out: list[Finding] = []
    for node, pkg in _imports(ps):
        low = pkg.lower()
        if (low in seen
                or _is_stdlib(pkg, ps.language)
                or _variants(pkg) & manifest
                or _is_local_module(pkg, local_root)):
            continue
        seen.add(low)
        near = _nearest(low, manifest)
        detail = (f"'{pkg}' is not in the known-package manifest."
                  + (f" A widely used package with a very similar name is '{near}'."
                     if near else ""))
        out.append(Finding(
            rule_id="CS006",
            title="Unrecognised dependency",
            severity=Severity.HIGH if near else Severity.MEDIUM,
            cwe="CWE-1104",
            owasp="A06:2021 - Vulnerable and Outdated Components",
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            column=node.start_point[1],
            snippet=ps.snippet(node),
            language=ps.language,
            explanation=detail,
        ))
    return out


def _levenshtein(a: str, b: str, cap: int = 2) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _nearest(name: str, manifest: frozenset[str]) -> str:
    best, best_d = "", 99
    for cand in manifest:
        d = _levenshtein(name, cand)
        if 0 < d < best_d:
            best, best_d = cand, d
    return best if best_d <= 2 else ""
