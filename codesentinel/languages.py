"""tree-sitter language loading. One place, cached, so parsers are built once."""
from __future__ import annotations

from functools import lru_cache

import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
from tree_sitter import Language, Parser

from .models import Language as Lang


@lru_cache(maxsize=None)
def get_language(lang: Lang) -> Language:
    if lang is Lang.PYTHON:
        return Language(tspy.language())
    if lang is Lang.JAVASCRIPT:
        return Language(tsjs.language())
    raise ValueError(f"unsupported language: {lang}")


@lru_cache(maxsize=None)
def get_parser(lang: Lang) -> Parser:
    return Parser(get_language(lang))


def detect_language(filename: str, code: str = "") -> Lang:
    """Filename first, then a cheap content heuristic."""
    lower = filename.lower()
    if lower.endswith((".py", ".pyi")):
        return Lang.PYTHON
    if lower.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        return Lang.JAVASCRIPT
    if "def " in code and ("import " in code or "print(" in code):
        return Lang.PYTHON
    return Lang.JAVASCRIPT if ("function " in code or "const " in code) else Lang.PYTHON
