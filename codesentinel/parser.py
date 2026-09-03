"""Parsing and node helpers shared by the rule engine and the feature extractor."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from tree_sitter import Node, Tree

from .languages import get_language, get_parser
from .models import Language as Lang


@dataclass
class ParsedSource:
    code: str
    source: bytes
    tree: Tree
    language: Lang

    @property
    def root(self) -> Node:
        return self.tree.root_node

    def text(self, node: Node) -> str:
        return self.source[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def line_of(self, node: Node) -> int:
        return node.start_point[0] + 1

    def snippet(self, node: Node, max_len: int = 160) -> str:
        raw = self.text(node).strip().replace("\n", " ")
        return raw if len(raw) <= max_len else raw[: max_len - 1] + "..."


def parse(code: str, language: Lang) -> ParsedSource:
    """Parse source. tree-sitter recovers from syntax errors, so a partially
    broken file still yields a usable tree - which matters, because AI-generated
    code arrives mid-edit."""
    source = bytes(code, "utf-8")
    tree = get_parser(language).parse(source)
    return ParsedSource(code=code, source=source, tree=tree, language=language)


def walk(node: Node) -> Iterator[Node]:
    """Depth-first traversal, node included."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def nodes_of_type(root: Node, *types: str) -> Iterator[Node]:
    wanted = set(types)
    for n in walk(root):
        if n.type in wanted:
            yield n


def ancestors(node: Node) -> Iterator[Node]:
    cur = node.parent
    while cur is not None:
        yield cur
        cur = cur.parent


def enclosing_function(node: Node) -> Node | None:
    fn_types = {
        "function_definition",          # python
        "function_declaration",         # js
        "function_expression",
        "arrow_function",
        "method_definition",
    }
    for a in ancestors(node):
        if a.type in fn_types:
            return a
    return None


def max_depth(node: Node) -> int:
    """Deepest nesting of block-like constructs - a proxy for complexity."""
    block_types = {
        "block", "if_statement", "for_statement", "while_statement",
        "try_statement", "with_statement", "switch_statement",
    }
    best = 0

    def rec(n: Node, d: int) -> None:
        nonlocal best
        nd = d + 1 if n.type in block_types else d
        best = max(best, nd)
        for c in n.children:
            rec(c, nd)

    rec(node, 0)
    return best


def query(language: Lang, pattern: str):
    return get_language(language).query(pattern)


def captures(q, node: Node) -> dict[str, list[Node]]:
    """Normalise tree-sitter capture output across binding versions.

    0.23 returns dict[name, list[Node]]; older builds return list[(Node, name)].
    Handling both means a dependency bump never silently empties your rules.
    """
    raw = q.captures(node)
    if isinstance(raw, dict):
        return raw
    out: dict[str, list[Node]] = {}
    for n, name in raw:
        out.setdefault(name, []).append(n)
    return out
