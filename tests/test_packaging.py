"""Packaging invariants.

These exist because a dependency was once installed ad hoc during development
and never added to requirements.txt. Every machine that already had it kept
working; CI, which starts clean, did not. A developer's environment is the worst
possible place to discover what a package needs, so assert it instead.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "codesentinel"

# Modules the package may import without declaring: the standard library, itself,
# and anything guarded behind a try/except as an optional extra.
OPTIONAL = {"llama_cpp"}


def _declared() -> set[str]:
    """Distribution names in requirements.txt, normalised to import-ish form."""
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        dist = re.split(r"[=<>!~\[; ]", line)[0].strip().lower()
        names.add(dist)
        names.add(dist.replace("-", "_"))
    return names


def _imported() -> set[str]:
    """Top-level modules imported anywhere in the package."""
    found = set()
    for path in PKG.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    found.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    found.add(node.module.split(".")[0])
    return found


def test_every_third_party_import_is_declared():
    """The bug this test exists for: `import tree_sitter_java` shipped in
    languages.py while requirements.txt still listed only python and javascript.
    Local machines had it from an ad-hoc pip install; CI did not, and every
    single job failed at collection."""
    declared = _declared()
    stdlib = set(sys.stdlib_module_names)

    undeclared = sorted(
        mod for mod in _imported()
        if mod not in stdlib
        and mod != "codesentinel"
        and mod not in OPTIONAL
        and mod.lower() not in declared
        and mod.lower().replace("_", "-") not in declared
    )
    assert undeclared == [], (
        "these modules are imported by the package but are not in "
        f"requirements.txt: {undeclared}"
    )


def test_every_declared_dependency_is_importable():
    """The reverse check: requirements.txt must not list something the
    environment cannot actually provide."""
    import importlib
    for dist in sorted(_declared()):
        if "_" in dist or dist in {"onnxruntime", "numpy", "typer", "rich"}:
            continue
        module = dist.replace("-", "_")
        if module in {"tree_sitter", "tree_sitter_python", "tree_sitter_javascript",
                      "tree_sitter_java"}:
            importlib.import_module(module)


@pytest.mark.parametrize("language", ["python", "javascript", "java"])
def test_every_declared_language_actually_parses(language):
    """A Language enum member with no grammar installed is a crash waiting for
    the first file of that type."""
    from codesentinel.models import Language
    from codesentinel.parser import parse
    ps = parse("", Language(language))
    assert ps.root is not None


def test_language_enum_and_cli_extensions_agree():
    """Every language we can parse must have at least one file extension that
    routes to it, or the CLI can never reach it."""
    from codesentinel.cli import EXTENSIONS
    from codesentinel.languages import detect_language
    from codesentinel.models import Language
    reachable = {detect_language(f"x{ext}") for ext in EXTENSIONS}
    assert set(Language) <= reachable
