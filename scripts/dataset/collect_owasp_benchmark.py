"""OWASP Benchmark (BenchmarkJava) -> Records.

https://github.com/OWASP-Benchmark/BenchmarkJava  ·  Apache-2.0

Why this source is worth having first: 2,740 Java test cases, each labelled by
the project itself with a CWE *and* whether it is a real vulnerability. The
false rows are the valuable half - same category, same imports, same shape as
the true rows, and safe. That is the hard-negative structure a model needs in
order to learn security rather than style, and it is handed to us rather than
constructed by us.

Its limitation, which belongs in any claim made from it: these are synthetic
test cases written to exercise scanners, not code anyone shipped. A model that
scores well here has learned this generator's idioms. Juliet has the same
caveat. CVEfixes is the one that does not.

    python scripts/dataset/collect_owasp_benchmark.py --clone
    python scripts/dataset/collect_owasp_benchmark.py --repo /path/to/BenchmarkJava
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from scripts.dataset.record import Record, write_jsonl        # noqa: E402

REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
TESTCODE = Path("src/main/java/org/owasp/benchmark/testcode")


def clone(dest: Path) -> Path:
    if dest.exists():
        print(f"  reusing {dest}")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  cloning {REPO_URL} (shallow) ...")
    subprocess.run(["git", "clone", "--depth", "1", "-q", REPO_URL, str(dest)],
                   check=True)
    return dest


def _expected_results(repo: Path) -> Path:
    hits = sorted(repo.glob("expectedresults-*.csv"))
    if not hits:
        raise SystemExit(f"no expectedresults-*.csv in {repo}")
    return hits[-1]


def collect(repo: Path) -> list[Record]:
    results = _expected_results(repo)
    print(f"  labels: {results.name}")

    records: list[Record] = []
    missing = 0
    with results.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            # Header fields carry leading spaces in this file.
            row = {k.strip().lstrip("# ").strip(): (v or "").strip()
                   for k, v in row.items() if k}
            name = row.get("test name") or ""
            if not name:
                continue
            source_file = repo / TESTCODE / f"{name}.java"
            if not source_file.exists():
                missing += 1
                continue

            vulnerable = row.get("real vulnerability", "").lower() == "true"
            cwe = row.get("cwe", "")

            # Grouping is a judgement call and worth stating. Benchmark
            # exercises each sink with many data-flow variants, so neighbouring
            # ids in the same category are near-duplicates and must not be split
            # apart. But grouping on the category alone sends an entire class to
            # the test fold, so the model never trains on it and its recall is
            # zero by construction. Blocks of 100 ids within a category keep the
            # twins together while leaving every category present in every fold.
            digits = "".join(ch for ch in name if ch.isdigit())
            block = int(digits or 0) // 100
            category = row.get("category", "unknown")

            records.append(Record(
                source="owasp-benchmark",
                group=f"owasp:{category}:{block:02d}",
                path=str(source_file.relative_to(repo)),
                language="java",
                code=source_file.read_text(encoding="utf-8", errors="replace"),
                # A negative sample carries no CWE: it is this category's safe
                # twin, and labelling it with the CWE would invert its meaning.
                cwes=[cwe] if (vulnerable and cwe) else [],
                is_vulnerable=vulnerable,
                meta={"category": category, "cwe_raw": cwe, "block": block},
            ))
    if missing:
        print(f"  {missing} rows had no matching .java file (skipped)")
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, help="Existing BenchmarkJava checkout.")
    ap.add_argument("--clone", action="store_true", help="Shallow-clone it first.")
    ap.add_argument("--out", type=Path,
                    default=Path("data/raw/owasp_benchmark.jsonl"))
    args = ap.parse_args()

    repo = args.repo
    if args.clone or repo is None:
        repo = clone(repo or Path("data/sources/BenchmarkJava"))
    if not repo.exists():
        raise SystemExit(f"{repo} does not exist. Pass --clone or --repo.")

    records = collect(repo)
    n = write_jsonl(records, args.out)
    pos = sum(1 for r in records if r.is_vulnerable)
    print(f"\n{args.out}: {n} records  ({pos} vulnerable, {n - pos} safe twins)")


if __name__ == "__main__":
    main()
