"""Turn collected records into the feature matrix the model trains on.

    python scripts/dataset/collect_owasp_benchmark.py --clone
    python scripts/build_dataset.py
    # -> data/processed/dataset.csv  (52 features + 13 labels + a group column)

The feature order is FEATURE_NAMES, and FEATURE_VERSION is written into the
output. Training must copy both into feature_scaler.json, because inference
refuses to run against a vector whose names or version it does not recognise -
a silent reorder produces confident wrong scores, which is worse than an error.
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codesentinel.deps.manifest import known_packages       # noqa: E402
from codesentinel.features.extract import (                 # noqa: E402
    FEATURE_NAMES, FEATURE_VERSION, extract_features,
)
from codesentinel.models import Language                    # noqa: E402
from codesentinel.parser import parse                       # noqa: E402
from codesentinel.triage.labels import label_vector         # noqa: E402
from codesentinel.triage.model import CLASS_ORDER           # noqa: E402
from scripts.dataset.record import read_jsonl               # noqa: E402


def build(inputs: list[Path], out: Path, drop_unlabelled: bool) -> None:
    rows: list[dict] = []
    seen_code: set[int] = set()
    stats = Counter()

    for path in inputs:
        if not path.exists():
            print(f"  skipping {path} (not found)")
            continue
        n_before = len(rows)
        for rec in read_jsonl(path):
            stats["read"] += 1
            try:
                language = Language(rec.language)
            except ValueError:
                stats["bad-language"] += 1
                continue

            # Exact-duplicate source text is common across these corpora and
            # inflates whichever split it lands in.
            fingerprint = hash(rec.code)
            if fingerprint in seen_code:
                stats["duplicate"] += 1
                continue
            seen_code.add(fingerprint)

            labels = label_vector(rec.cwes, CLASS_ORDER)
            if rec.is_vulnerable and not any(labels):
                # A vulnerable sample whose CWE we do not cover is not a
                # negative - it is a positive for a class that does not exist
                # here. Training on it as clean teaches the opposite of truth.
                stats["unmapped-cwe"] += 1
                if drop_unlabelled:
                    continue

            try:
                ps = parse(rec.code, language)
                features = extract_features(ps, set(known_packages(language)))
            except Exception as exc:                        # noqa: BLE001
                stats["parse-failed"] += 1
                print(f"    parse failed for {rec.path}: {exc}")
                continue

            rows.append({
                "group": rec.group,
                "source": rec.source,
                "language": rec.language,
                "path": rec.path,
                **dict(zip(FEATURE_NAMES, features)),
                **{f"y_{cls}": v for cls, v in zip(CLASS_ORDER, labels)},
            })
            stats["kept"] += 1
        print(f"  {path.name}: +{len(rows) - n_before}")

    if not rows:
        raise SystemExit("no rows produced - run a collector first")

    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0])
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    (out.parent / "feature_version.txt").write_text(
        f"{FEATURE_VERSION}\n", encoding="utf-8")

    print(f"\n{out}: {len(rows)} rows x {len(FEATURE_NAMES)} features")
    print(f"feature_version {FEATURE_VERSION}")
    print("\nlabel balance:")
    for cls in CLASS_ORDER:
        pos = sum(r[f"y_{cls}"] for r in rows)
        bar = "#" * max(1, round(40 * pos / len(rows))) if pos else ""
        print(f"  {cls}  {pos:6d}  {100 * pos / len(rows):5.1f}%  {bar}")
    n_clean = sum(1 for r in rows if not any(r[f"y_{c}"] for c in CLASS_ORDER))
    print(f"\n  no positive label (clean): {n_clean}  "
          f"({100 * n_clean / len(rows):.1f}%)")
    print("\ngroups:", len({r["group"] for r in rows}),
          "- split on these, never on rows")
    print("counters:", dict(stats))

    thin = [c for c in CLASS_ORDER
            if sum(r[f"y_{c}"] for r in rows) < 30]
    if thin:
        print(f"\nWARNING: under 30 positives for {thin}.")
        print("A per-class F1 computed from that few samples is noise. Either")
        print("add a source that covers them, or report those classes as")
        print("untrained rather than quoting a number.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", type=Path, default=Path("data/raw"),
                    help="Directory of collector .jsonl output.")
    ap.add_argument("--out", type=Path, default=Path("data/processed/dataset.csv"))
    ap.add_argument("--keep-unmapped", action="store_true",
                    help="Keep vulnerable samples whose CWE we do not cover "
                         "(they become all-zero rows - usually wrong).")
    args = ap.parse_args()

    inputs = sorted(args.raw.glob("*.jsonl"))
    if not inputs:
        raise SystemExit(f"no .jsonl files in {args.raw} - run a collector first")
    build(inputs, args.out, drop_unlabelled=not args.keep_unmapped)


if __name__ == "__main__":
    main()
