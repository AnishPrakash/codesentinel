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

try:
    import httpx
except ImportError:                                     # noqa: BLE001
    sys.exit("This script needs httpx:  pip install httpx")

OUT = Path(__file__).resolve().parent.parent / "codesentinel" / "data" / "manifests"

HEADER = (
    "# Offline {registry} manifest.\n"
    "# Rebuilt by scripts/build_manifests.py, merged with the curated seed below.\n"
    "# A scan never touches the network - this file is why.\n"
)

# Import names that do not equal their distribution name, so a registry dump
# alone would not contain them. Anything CodeSentinel itself imports MUST be
# here, or the scanner reports its own source as an unrecognised dependency and
# tests/test_new_classes.py::test_codesentinel_is_clean_on_its_own_source fails.
PY_ALIASES = {
    "llama_cpp", "llama-cpp-python",          # import llama_cpp
    "tree_sitter", "tree_sitter_python", "tree_sitter_javascript", "tree_sitter_java",
    "yaml", "pyyaml",                          # import yaml
    "cv2", "opencv-python",                    # import cv2
    "PIL", "pillow",                           # import PIL
    "sklearn", "scikit-learn",
    "bs4", "beautifulsoup4",
    "dateutil", "python-dateutil",
    "dotenv", "python-dotenv",
    "jwt", "pyjwt",
    "serial", "pyserial",
    "OpenSSL", "pyopenssl",
    "Crypto", "pycryptodome",
    "google", "googleapis-common-protos",
    "attr", "attrs",
    "docx", "python-docx",
    "pptx", "python-pptx",
    "fitz", "pymupdf",
    "magic", "python-magic",
    "usb", "pyusb",
    "win32com", "pywin32",
}

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
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    rows = httpx.get(url, timeout=60).json()["rows"][:n]
    names = {r["project"].lower() for r in rows}
    path = OUT / "pypi_top.txt"
    names |= {a.lower() for a in PY_ALIASES}
    if merge:
        names |= _existing(path)
    _write(path, "PyPI", names)


def npm(n: int, merge: bool) -> None:
    names: set[str] = set()
    with httpx.Client(timeout=60) as c:
        for offset in range(0, n, 250):
            r = c.get("https://registry.npmjs.org/-/v1/search",
                      params={"text": "boost-exact:false", "size": 250, "from": offset})
            if r.status_code != 200:
                print(f"  npm search stopped at offset {offset} (HTTP {r.status_code})")
                break
            objs = r.json().get("objects", [])
            if not objs:
                break
            names |= {o["package"]["name"].lower() for o in objs}
    path = OUT / "npm_top.txt"
    names |= {a.lower() for a in JS_ALIASES}
    if merge:
        names |= _existing(path)
    if not names:
        sys.exit("npm returned nothing - leaving the committed manifest alone.")
    _write(path, "npm", names)


def main() -> None:
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
