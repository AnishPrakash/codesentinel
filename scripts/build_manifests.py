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


def pypi(n: int, merge: bool) -> None:
    import httpx

    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    rows = httpx.get(url, timeout=60).json()["rows"][:n]
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


def npm(n: int, merge: bool) -> None:
    import httpx

    candidates: set[str] = set()
    with httpx.Client(timeout=60, follow_redirects=True) as c:
        for offset in range(0, n * 3, 250):     # over-fetch; most get filtered out
            r = c.get("https://registry.npmjs.org/-/v1/search",
                      params={"text": "boost-exact:false", "size": 250,
                              "from": offset, "popularity": 1.0,
                              "quality": 0.0, "maintenance": 0.0})
            if r.status_code != 200:
                print(f"  npm search stopped at offset {offset} (HTTP {r.status_code})")
                break
            objs = r.json().get("objects", [])
            if not objs:
                break
            candidates |= {o["package"]["name"].lower() for o in objs}
            if len(candidates) >= n * 3:
                break

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
    if args.only != "npm":
        pypi(args.count, merge)
    if args.only != "pypi":
        npm(args.count, merge)

    print("\nNow re-run the tests before committing:")
    print("  pytest -q")
    print("  cs scan codesentinel/ --fail-on critical")
    print("A manifest that drops an alias makes the scanner fire on its own source.")


if __name__ == "__main__":
    main()
