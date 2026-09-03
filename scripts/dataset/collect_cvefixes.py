"""CVEfixes -> Records. The only source here made of code people shipped.

https://github.com/secureIT-project/CVEfixes  ·  CC BY 4.0 (data), MIT (tools)

CVEfixes is a SQLite database built from real CVEs and the commits that fixed
them. For each fixed method it stores the code before and after the fix, which
is the patch-pair structure this whole approach depends on: the "before" is a
real vulnerability and the "after" is the same function, by the same author, in
the same style, without it. A model cannot separate those on style.

Get the database (several GB) either by downloading the published dump or by
running their builder:

    # published dump (check the repo README for the current link)
    #   https://zenodo.org/records/7029359
    # or build it yourself:
    git clone https://github.com/secureIT-project/CVEfixes
    #   follow their README - it needs a GitHub token and takes hours

Then:
    python scripts/dataset/collect_cvefixes.py --db /path/to/CVEfixes.db

NOTE: this collector could not be run against the real database while it was
written (zenodo.org was unreachable from that environment). The schema below
follows the CVEfixes documentation, and --inspect prints the tables and columns
your copy actually has so you can correct the names in one place if their schema
has moved. Run with --limit 200 first.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from codesentinel.triage.labels import class_for_cwe          # noqa: E402
from scripts.dataset.record import Record, write_jsonl        # noqa: E402

EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mjs": "javascript",
    ".java": "java",
}

# CVEfixes: cve -> cwe_classification -> cwe, and fixes -> commits -> file_change
# -> method_change. Method-level rows carry both versions of the code.
QUERY = """
select
    m.code                as code,
    m.before_change       as before_change,
    m.name                as method_name,
    f.filename            as filename,
    f.repo_url            as repo_url,
    cc.cwe_id             as cwe_id
from method_change  m
join file_change    f  on f.file_change_id = m.file_change_id
join commits        c  on c.hash           = f.hash
join fixes          x  on x.hash           = c.hash
join cwe_classification cc on cc.cve_id    = x.cve_id
where m.code is not null and length(m.code) > 40
"""


def inspect(db: Path) -> None:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    tables = [r[0] for r in conn.execute(
        "select name from sqlite_master where type='table' order by name")]
    print(f"{len(tables)} tables in {db.name}:\n")
    for t in tables:
        cols = [r[1] for r in conn.execute(f"pragma table_info('{t}')")]
        print(f"  {t}")
        print(f"      {', '.join(cols)}")
    conn.close()
    print("\nIf these column names differ from QUERY in this file, edit QUERY. "
          "That is the only place the schema is assumed.")


def _language(filename: str) -> str | None:
    return EXT_TO_LANGUAGE.get(Path(filename or "").suffix.lower())


def _repo_group(repo_url: str) -> str:
    slug = (repo_url or "").rstrip("/").split("/")[-2:]
    return "cvefixes:" + "/".join(s for s in slug if s)


def collect(db: Path, limit: int | None) -> list[Record]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    records: list[Record] = []
    skipped = {"language": 0, "cwe": 0, "empty": 0}
    seen: set[tuple[str, str]] = set()

    sql = QUERY + (f" limit {int(limit)}" if limit else "")
    for row in conn.execute(sql):
        language = _language(row["filename"])
        if language is None:
            skipped["language"] += 1
            continue

        cwe = str(row["cwe_id"] or "")
        if not class_for_cwe(cwe):
            # Not a weakness we model. Dropping beats forcing it into the
            # nearest class - a mislabelled sample teaches the wrong thing.
            skipped["cwe"] += 1
            continue

        group = _repo_group(row["repo_url"])
        name = row["method_name"] or "method"

        # before_change is the vulnerable version, code is the fixed one. The
        # pair is the point: same author, same style, one difference.
        before = row["before_change"]
        after = row["code"]

        for text, vulnerable, tag in ((before, True, "before"), (after, False, "after")):
            if not text or len(text.strip()) < 40:
                skipped["empty"] += 1
                continue
            key = (group, str(hash(text)))
            if key in seen:
                continue
            seen.add(key)
            records.append(Record(
                source="cvefixes",
                # Split on the repository. A function and its own patched twin
                # must never land on opposite sides of the split.
                group=group,
                path=f"{row['filename']}#{name}:{tag}",
                language=language,
                code=text,
                cwes=[cwe] if vulnerable else [],
                is_vulnerable=vulnerable,
                meta={"method": name, "version": tag},
            ))

    conn.close()
    print(f"  skipped: {skipped}")
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path, required=True, help="CVEfixes SQLite file.")
    ap.add_argument("--out", type=Path, default=Path("data/raw/cvefixes.jsonl"))
    ap.add_argument("--limit", type=int, help="Rows to read (smoke test).")
    ap.add_argument("--inspect", action="store_true",
                    help="Print the schema and exit - run this first.")
    args = ap.parse_args()

    if not args.db.exists():
        raise SystemExit(f"{args.db} does not exist")
    if args.inspect:
        inspect(args.db)
        return

    records = collect(args.db, args.limit)
    n = write_jsonl(records, args.out)
    pos = sum(1 for r in records if r.is_vulnerable)
    langs = {}
    for r in records:
        langs[r.language] = langs.get(r.language, 0) + 1
    print(f"\n{args.out}: {n} records  ({pos} vulnerable, {n - pos} fixed twins)")
    print(f"languages: {langs}")
    print(f"repositories: {len({r.group for r in records})}")


if __name__ == "__main__":
    main()
