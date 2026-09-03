"""The manifests are a security control, so their contents are asserted.

CS006's entire claim is that a name it does not recognise is worth a second
look. That claim is only as good as the recognised list: pad it with registry
sludge and the rule stops distinguishing "popular package" from "name a model
made up". A rebuild that fetches the wrong thing produces a file that looks
completely normal, so the check has to be here rather than in the reviewer's
eye.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "codesentinel" / "data" / "manifests"


def _load_builder():
    """Import the script by path; scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location(
        "build_manifests", ROOT / "scripts" / "build_manifests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)      # must not need httpx at import time
    return module


def _names(path: Path) -> set[str]:
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


@pytest.mark.parametrize("filename", ["npm_top.txt", "pypi_top.txt"])
def test_committed_manifest_has_no_junk(filename: str) -> None:
    builder = _load_builder()
    names = _names(MANIFESTS / filename)
    junk = sorted(n for n in names if any(m in n for m in builder.JUNK_MARKERS))
    assert not junk, f"{filename} contains registry spam: {junk[:10]}"


def test_committed_manifests_keep_their_sentinels() -> None:
    builder = _load_builder()
    npm = _names(MANIFESTS / "npm_top.txt")
    pypi = _names(MANIFESTS / "pypi_top.txt")
    assert builder.NPM_SENTINELS <= npm, sorted(builder.NPM_SENTINELS - npm)
    assert builder.PYPI_SENTINELS <= pypi, sorted(builder.PYPI_SENTINELS - pypi)


def test_the_gate_rejects_a_sludge_rebuild() -> None:
    """The check that matters: this exact set is what npm search returned.

    A rebuild once produced 2,417 names of which 59 were cbd/casino/keto spam
    and most of the rest were abandoned scoped packages. It passed every test in
    this repo. The gate exists so that cannot happen silently again.
    """
    builder = _load_builder()
    sludge = builder.NPM_SENTINELS | {"1st-vitality-cbd-gummies", "@1tool/js-boost"}
    assert not builder._sane(sludge, builder.NPM_SENTINELS, "npm")


def test_the_gate_rejects_a_rebuild_that_lost_the_popular_packages() -> None:
    builder = _load_builder()
    assert not builder._sane({"express", "lodash"}, builder.NPM_SENTINELS, "npm")


def test_the_gate_accepts_a_good_rebuild() -> None:
    # A gate that never passes is a gate someone deletes.
    builder = _load_builder()
    good = set(builder.NPM_SENTINELS) | {"rimraf", "glob", "@babel/core"}
    assert builder._sane(good, builder.NPM_SENTINELS, "npm")


def test_no_alias_import_is_reported_as_unrecognised() -> None:
    """The contract the firewall actually has to keep.

    The manifest holds *distribution* names (pyyaml); source code contains
    *import* names (yaml). aliases.py bridges them, and the two are separate
    files that can drift - when they do, CS006 fires on perfectly correct code,
    which is the fastest way to make a security tool ignorable. So the assertion
    is behavioural: import it, scan it, expect silence.
    """
    from codesentinel.deps.aliases import IMPORT_TO_DISTRIBUTION
    from codesentinel.models import Language
    from codesentinel.parser import parse
    from codesentinel.rules.engine import run_rules

    flagged = []
    for import_name in sorted(IMPORT_TO_DISTRIBUTION):
        parsed = parse(f"import {import_name}\n", Language.PYTHON)
        if any(f.rule_id == "CS006" for f in run_rules(parsed)):
            flagged.append(import_name)
    assert not flagged, f"CS006 fires on correct imports: {flagged}"


def test_a_moved_source_is_reported_as_a_moved_source() -> None:
    """The failure that actually happened, pinned.

    hugovk.github.io kept answering after the dataset moved to hugovk.dev - with
    an HTML 404 page. httpx handed that to json.loads and the user got
    "Expecting value: line 1 column 1", which points at the data being malformed
    rather than at the URL being wrong. A wrong diagnosis costs more than a
    failure does.
    """
    import httpx

    builder = _load_builder()

    def html_404(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, html="<!doctype html><title>404</title>")

    transport = httpx.MockTransport(html_404)
    real_get = httpx.get
    httpx.get = lambda url, **kw: httpx.Client(transport=transport).get(url)
    try:
        with pytest.raises(RuntimeError) as err:
            builder._fetch_json("https://example.invalid/x.json", "PyPI top packages")
    finally:
        httpx.get = real_get
    assert "HTTP 404" in str(err.value)


def test_an_html_body_with_a_200_is_also_caught() -> None:
    # Some hosts serve a landing page with 200 instead of a 404.
    import httpx

    builder = _load_builder()

    def html_200(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<!doctype html><title>hi</title>")

    transport = httpx.MockTransport(html_200)
    real_get = httpx.get
    httpx.get = lambda url, **kw: httpx.Client(transport=transport).get(url)
    try:
        with pytest.raises(RuntimeError) as err:
            builder._fetch_json("https://example.invalid/x.json", "PyPI top packages")
    finally:
        httpx.get = real_get
    assert "probably moved" in str(err.value)


def test_every_sentinel_is_also_a_query_term() -> None:
    """The gate refuses to write without these, so the search must ask for them.

    A 7,127-candidate pool built from 33 terms contained 13 of 14 sentinels.
    The one it missed, dotenv, was simply never queried - no term in the list
    surfaced it. Hoping a neighbouring term happens to reach a package the gate
    treats as mandatory is not a plan.
    """
    builder = _load_builder()
    missing = builder.NPM_SENTINELS - set(builder.NPM_QUERY_TERMS)
    assert not missing, f"sentinels never queried: {sorted(missing)}"


def test_query_terms_are_not_empty_strings() -> None:
    """An empty query is what returned registry sludge in the first place."""
    builder = _load_builder()
    assert all(t.strip() for t in builder.NPM_QUERY_TERMS)
    assert len(builder.NPM_QUERY_TERMS) > 50
