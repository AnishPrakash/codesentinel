"""Juliet Test Suite for Java (NIST SARD) -> Records.

https://samate.nist.gov/SARD/test-suites/juliet  ·  Public domain

Download (the zip is ~50 MB, the Java suite):
    https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip
    unzip it, then:  python scripts/dataset/collect_juliet.py --root <unzipped>

Juliet's structure is the reason it is worth the download: every test case
contains a `bad()` method that is genuinely vulnerable and one or more `good*()`
methods that are the same logic made safe. Extracting them as separate samples
gives a matched pair per case, and the CWE is stated in the path and filename
rather than inferred.

Two things this collector deliberately does not do. It does not treat a whole
file as one sample, because a file holds both the bad and the good method and
the label would be meaningless. And it does not guess a CWE when the filename
does not carry one - the sample is dropped instead.

NOTE: this collector could not be run against the real archive while it was
written (samate.nist.gov was unreachable from that environment). Its parsing is
covered by tests/test_dataset_collectors.py against fixtures built to Juliet's
documented shape. Run it on a handful of cases first and eyeball the output
before trusting a full run.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from scripts.dataset.record import Record, write_jsonl        # noqa: E402

# CWE89_SQL_Injection__connect_tcp_execute_01.java
CWE_IN_NAME = re.compile(r"CWE(\d+)_", re.IGNORECASE)

# Juliet marks the vulnerable path `bad` and the safe ones `good`, `good1`,
# `goodG2B`, `goodB2G`, ... The B2G/G2B pairs are both safe: they differ in
# which half of the flow was fixed.
BAD_METHOD = re.compile(r"\b(public|private|protected)\s+[\w<>\[\], ]+\s+bad\s*\(")
GOOD_METHOD = re.compile(
    r"\b(public|private|protected)\s+[\w<>\[\], ]+\s+(good\w*)\s*\(")


def _extract_method(source: str, start: int) -> str | None:
    """Return the method body starting at `start`, matched on braces.

    Brace counting is crude but correct enough here: Juliet is generated code
    with no string literals containing unbalanced braces in method bodies.
    """
    brace = source.find("{", start)
    if brace == -1:
        return None
    depth, i = 0, brace
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    return None


def _class_wrap(name: str, body: str) -> str:
    """A bare method does not parse as a compilation unit. Wrap it so the
    feature extractor sees the structure it expects."""
    return f"public class {name} {{\n{body}\n}}\n"


def collect(root: Path, limit: int | None = None) -> list[Record]:
    records: list[Record] = []
    files = sorted(root.rglob("CWE*_*.java"))
    if limit:
        files = files[:limit]
    print(f"  {len(files)} candidate files under {root}")

    no_cwe = no_method = 0
    for path in files:
        m = CWE_IN_NAME.search(path.name)
        if not m:
            no_cwe += 1
            continue
        cwe = f"CWE-{m.group(1)}"
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # The CWE directory is the split group: variants of one weakness live
        # together, and a repo-level split is what keeps a bad method and its
        # own good twin on the same side.
        group = f"juliet:{cwe}"
        stem = path.stem
        found_any = False

        bad = BAD_METHOD.search(source)
        if bad:
            body = _extract_method(source, bad.start())
            if body:
                found_any = True
                records.append(Record(
                    source="juliet", group=group, path=f"{path.name}#bad",
                    language="java", code=_class_wrap(stem, body),
                    cwes=[cwe], is_vulnerable=True,
                    meta={"method": "bad"},
                ))

        for gm in GOOD_METHOD.finditer(source):
            name = gm.group(2)
            body = _extract_method(source, gm.start())
            if not body:
                continue
            found_any = True
            records.append(Record(
                source="juliet", group=group, path=f"{path.name}#{name}",
                language="java", code=_class_wrap(stem, body),
                cwes=[], is_vulnerable=False,
                meta={"method": name},
            ))

        if not found_any:
            no_method += 1

    print(f"  skipped: {no_cwe} without a CWE in the name, "
          f"{no_method} with no bad/good method found")
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True,
                    help="Unzipped Juliet Java suite (the dir holding src/ or testcases/).")
    ap.add_argument("--out", type=Path, default=Path("data/raw/juliet.jsonl"))
    ap.add_argument("--limit", type=int, help="Parse only the first N files (smoke test).")
    args = ap.parse_args()

    if not args.root.exists():
        raise SystemExit(f"{args.root} does not exist")

    records = collect(args.root, args.limit)
    n = write_jsonl(records, args.out)
    pos = sum(1 for r in records if r.is_vulnerable)
    print(f"\n{args.out}: {n} records  ({pos} vulnerable, {n - pos} safe)")
    if n and pos / n > 0.6:
        print("WARNING: mostly positives. Juliet should yield more good methods "
              "than bad ones - check the good-method regex against your copy.")


if __name__ == "__main__":
    main()
