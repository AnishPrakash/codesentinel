"""Build the offline package manifests. Run once, with network, then commit.

Producing these at scan time would defeat the point: resolving a name against a
live registry is exactly the action a slopsquatted package wants you to take.

This script MERGES with what is already committed rather than replacing it, for
one specific reason: a registry lists *distribution* names, and CS006 sees
*import* names. Those usually match, and sometimes do not - `import llama_cpp`
comes from the distribution `llama-cpp-python`, and no amount of hyphen/underscore
normalisation bridges that. Replacing the file wholesale would silently drop
every such alias and make the scanner fire on correct code.

    python scripts/build_manifests.py            # merge (default, safe)
    python scripts/build_manifests.py --replace  # discard the existing list
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# httpx is imported inside the functions that need it, never at module scope.
# A module that exits the interpreter when imported is hostile to every
# consumer - including the test that reads the alias table out of this file,
# which is exactly how this broke CI once.

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "codesentinel" / "data" / "manifests"
sys.path.insert(0, str(ROOT))

HEADER = (
    "# Offline {registry} manifest.\n"
    "# Rebuilt by scripts/build_manifests.py, merged with the curated seed below.\n"
    "# A scan never touches the network - this file is why.\n"
)

# The alias table is package data, not script data: the firewall reads it at
# scan time so `import yaml` is not reported as an unrecognised dependency, and
# this script reads the same table so a rebuild cannot drop it. One source, so
# the two cannot drift apart.
from codesentinel.deps.aliases import ALL_KNOWN_SPELLINGS   # noqa: E402

PY_ALIASES = ALL_KNOWN_SPELLINGS

JS_ALIASES: set[str] = set()


def _existing(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def _write(path: Path, registry: str, names: set[str]) -> None:
    body = "\n".join(sorted(n for n in names if n))
    path.write_text(HEADER.format(registry=registry) + body + "\n", encoding="utf-8")
    print(f"{path.name}: {len(names)} packages")


# The dataset moved host once already (hugovk.github.io -> hugovk.dev), and the
# old address answers with an HTML 404 rather than an error, so the failure
# arrived as a JSONDecodeError from deep inside httpx. _fetch_json exists so a
# moved or broken source says so in one line.
PYPI_TOP_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"


def _fetch_json(url: str, what: str):
    import httpx

    r = httpx.get(url, timeout=60, follow_redirects=True)
    if r.status_code != 200:
        raise RuntimeError(f"{what}: HTTP {r.status_code} from {url}")
    ctype = r.headers.get("content-type", "")
    if "json" not in ctype:
        # An HTML body here means the URL moved, not that the data is malformed.
        raise RuntimeError(
            f"{what}: {url} returned {ctype or 'no content-type'}, not JSON. "
            "The source has probably moved - check the URL before editing anything else."
        )
    return r.json()


def pypi(n: int, merge: bool) -> None:
    body = _fetch_json(PYPI_TOP_URL, "PyPI top packages")
    if "rows" not in body:
        raise RuntimeError(
            f"PyPI top packages: no 'rows' key (got {sorted(body)[:6]}). "
            "The schema changed.")
    rows = body["rows"][:n]
    names = {r["project"].lower() for r in rows}
    path = OUT / "pypi_top.txt"
    names |= {a.lower() for a in PY_ALIASES}
    if merge:
        names |= _existing(path)
    if not _sane(names, PYPI_SENTINELS, "PyPI"):
        sys.exit("PyPI manifest not written. The committed one is untouched.")
    _write(path, "PyPI", names)


# The registry search endpoint is not a popularity ranking. Called with no
# query text it returns an arbitrary slice of npm, which in practice is mostly
# abandoned scoped packages and outright spam - cbd gummies, casinos, keto. A
# manifest padded with those is worse than a short one: CS006's entire claim is
# that an unrecognised name is worth a second look, and a name like
# "@ai-foundry/llm-sdk" sitting in the manifest is exactly the hallucinated
# dependency the rule exists to catch. So search only proposes candidates, and
# download counts decide.
MIN_DOWNLOADS_PER_MONTH = 10_000

# Packages that must survive any rebuild. Not a whitelist - a canary. If a
# rebuild loses these it did not fetch a popularity ranking, whatever it did
# fetch, and the result must not be written.
NPM_SENTINELS = frozenset({
    "react", "express", "lodash", "axios", "typescript", "webpack", "eslint",
    "jest", "vue", "next", "chalk", "commander", "dotenv", "moment",
})
PYPI_SENTINELS = frozenset({
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "boto3",
    "click", "pytest", "setuptools", "pyyaml", "cryptography",
})

# Substrings that have no business in a manifest of popular developer packages.
# Present only to make a bad fetch loud; a legitimate package caught by one of
# these is a reason to edit the list, not to disable the check.
JUNK_MARKERS = (
    "cbd", "gummies", "casino", "porn", "keto", "weight-loss", "male-enhance",
    "slot-gacor", "viagra", "escort",
)


def _sane(names: set[str], sentinels: frozenset[str], registry: str) -> bool:
    """Would writing this set make the scanner worse?

    Two independent ways for a rebuild to go wrong, and neither raises on its
    own: the source stopped being a popularity ranking (sentinels vanish), or
    the source is returning registry sludge (junk markers appear). Both produce
    a file that looks fine and quietly degrades CS006.
    """
    missing = sorted(sentinels - names)
    junk = sorted(n for n in names if any(m in n for m in JUNK_MARKERS))
    ok = True
    if missing:
        print(f"  {registry}: REFUSING - {len(missing)} sentinel package(s) absent: "
              f"{missing[:8]}")
        ok = False
    if junk:
        print(f"  {registry}: REFUSING - {len(junk)} junk name(s) present, "
              f"e.g. {junk[:5]}")
        ok = False
    return ok


def _npm_downloads(client, batch: list[str]) -> dict[str, int]:
    """Last month's downloads. The bulk endpoint takes up to 128 unscoped names
    per call and rejects scoped ones, so those are asked for individually."""
    out: dict[str, int] = {}
    unscoped = [n for n in batch if not n.startswith("@")]
    scoped = [n for n in batch if n.startswith("@")]

    if unscoped:
        r = client.get("https://api.npmjs.org/downloads/point/last-month/"
                       + ",".join(unscoped))
        if r.status_code == 200:
            body = r.json()
            # One name comes back as a bare object, several as a mapping.
            rows = body if len(unscoped) > 1 else {unscoped[0]: body}
            for name, row in rows.items():
                if isinstance(row, dict) and row.get("downloads") is not None:
                    out[name.lower()] = int(row["downloads"])

    for name in scoped:
        r = client.get(f"https://api.npmjs.org/downloads/point/last-month/{name}")
        if r.status_code == 200 and isinstance(r.json().get("downloads"), int):
            out[name.lower()] = int(r.json()["downloads"])
    return out


# npm's search endpoint ranks results for a QUERY. Called with no query text it
# returns an arbitrary slice of the registry - which is how a rebuild once
# produced 2,417 names, 59 of them cbd/casino/keto spam. Given real query terms
# and popularity weighting it returns what you would expect: react, axios, jest,
# webpack. So the terms are the seed, and download counts are still the filter.
#
# The list is deliberately broad and boring: ecosystem names, layer names, and
# job-to-be-done words. It does not need to be exhaustive, because anything it
# surfaces still has to clear MIN_DOWNLOADS_PER_MONTH, and anything popular is
# reachable from several of these terms at once.
NPM_QUERY_TERMS = (
    "react vue angular svelte next nuxt remix astro ember backbone jquery "
    "node express koa fastify nest hapi restify socket websocket graphql rest "
    "webpack rollup vite esbuild parcel babel swc typescript tsc eslint prettier "
    "jest mocha vitest cypress playwright puppeteer testing mock chai sinon "
    "lodash ramda underscore immutable rxjs redux zustand mobx recoil "
    "axios fetch http client request superagent got undici "
    "css sass less postcss tailwind styled emotion bootstrap material chakra "
    "date time moment dayjs luxon timezone "
    "logger logging winston pino debug chalk colors "
    "cli commander yargs inquirer prompt ora spinner "
    "fs path glob rimraf mkdirp chokidar watch "
    "json yaml toml xml csv parser serializer schema validation zod joi ajv "
    "crypto hash uuid jwt bcrypt auth passport oauth session cookie "
    "database orm sql postgres mysql mongodb redis sqlite prisma sequelize knex "
    "aws azure google cloud sdk s3 lambda docker kubernetes "
    "image video canvas svg pdf chart d3 three animation "
    "i18n intl translation markdown template handlebars ejs "
    "queue worker cache stream buffer async promise event emitter "
    "types utils helpers polyfill shim compat browser dom react-native electron "
    "config env dotenv bundler compiler linter formatter monorepo package"
).split()

# Every sentinel is also a query term. Not circular - the sentinels are the
# packages the gate refuses to write a manifest without, so the search has to
# be asked for them explicitly rather than hoping a neighbouring term surfaces
# them. dotenv was missing from a 7,127-candidate pool for exactly that reason.
NPM_QUERY_TERMS = tuple(dict.fromkeys(NPM_QUERY_TERMS + sorted(NPM_SENTINELS)))


def _npm_search(client, term: str, offset: int) -> list[str] | None:
    """One page of popularity-ranked results, or None if the request failed.

    npm rate-limits, and a rate-limited page used to be skipped in silence. The
    result was a manifest missing express, lodash, jest and webpack while
    looking completely normal - the same silent degradation as the sludge run,
    only subtractive. So a failure is retried, and then reported.
    """
    import time

    for attempt in range(3):
        r = client.get("https://registry.npmjs.org/-/v1/search",
                       params={"text": term, "size": 250, "from": offset,
                               "popularity": 1.0, "quality": 0.0,
                               "maintenance": 0.0})
        if r.status_code == 200:
            return [o["package"]["name"].lower() for o in r.json().get("objects", [])]
        time.sleep(2 ** attempt)
    return None


def npm(n: int, merge: bool) -> None:
    import time

    import httpx

    candidates: set[str] = set()
    failed: list[str] = []
    with httpx.Client(timeout=60, follow_redirects=True) as c:
        for i, term in enumerate(NPM_QUERY_TERMS):
            page = _npm_search(c, term, 0)
            if page is None:
                failed.append(term)
                continue
            candidates |= set(page)
            if len(page) == 250:                       # a full page: ask for more
                more = _npm_search(c, term, 250)
                if more:
                    candidates |= set(more)
            time.sleep(0.2)                            # be a good citizen
            if (i + 1) % 20 == 0:
                print(f"    {i + 1}/{len(NPM_QUERY_TERMS)} terms, "
                      f"{len(candidates)} candidates")

        if len(failed) > len(NPM_QUERY_TERMS) // 10:
            sys.exit(f"npm search failed for {len(failed)} terms "
                     f"({failed[:5]}...). Rate-limited or offline - the "
                     "committed manifest is untouched.")
        if failed:
            print(f"  npm: {len(failed)} term(s) failed after retries: {failed}")

        print(f"  npm: {len(candidates)} candidates, checking download counts")
        ordered = sorted(candidates)
        popular: set[str] = set()
        for i in range(0, len(ordered), 128):
            batch = ordered[i:i + 128]
            for name, count in _npm_downloads(c, batch).items():
                if count >= MIN_DOWNLOADS_PER_MONTH:
                    popular.add(name)
            print(f"    {i + len(batch)}/{len(ordered)} checked, "
                  f"{len(popular)} kept", end="\r")
    print()

    path = OUT / "npm_top.txt"
    names = popular | {a.lower() for a in JS_ALIASES}
    if merge:
        names |= _existing(path)
    if not popular:
        sys.exit("npm returned nothing popular - leaving the committed manifest alone.")
    if not _sane(names, NPM_SENTINELS, "npm"):
        sys.exit("npm manifest not written. The committed one is untouched.")
    _write(path, "npm", names)


def main() -> None:
    try:
        import httpx                                    # noqa: F401
    except ImportError:
        raise SystemExit("This script needs httpx:  pip install httpx") from None

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--replace", action="store_true",
                    help="Discard the committed list instead of merging into it.")
    ap.add_argument("--count", type=int, default=8000, help="Packages per registry.")
    ap.add_argument("--only", choices=["pypi", "npm"], help="Rebuild just one.")
    args = ap.parse_args()

    merge = not args.replace

    # One registry failing must not skip the other. The first run of this
    # script died on PyPI and never attempted npm at all, which reads as "the
    # whole rebuild is broken" when half of it was fine.
    failures: list[str] = []
    for name, fn in (("pypi", pypi), ("npm", npm)):
        if args.only and args.only != name:
            continue
        try:
            fn(args.count, merge)
        except SystemExit:
            raise
        except Exception as exc:                      # noqa: BLE001
            failures.append(f"{name}: {exc}")
            print(f"  {name}: FAILED - {exc}")

    if failures:
        print("\nThe committed manifests for the failed registries are untouched.")
        raise SystemExit(1)

    print("\nNow re-run the tests before committing:")
    print("  pytest -q")
    print("  cs scan codesentinel/ --fail-on critical")
    print("A manifest that drops an alias makes the scanner fire on its own source.")


if __name__ == "__main__":
    main()
