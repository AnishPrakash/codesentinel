"""The one record shape every collector produces."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator


@dataclass
class Record:
    """One labelled code sample.

    `group` is what the train/val/test split is done on - a repository, or a
    Benchmark test-case family. Splitting on rows instead of groups lets a
    vulnerable function and its own fixed twin land on opposite sides, which
    inflates every metric and is the single most common way a vulnerability
    dataset lies to you.
    """
    source: str                    # "owasp-benchmark", "juliet", "cvefixes"
    group: str                     # split key: repo or test family
    path: str                      # provenance, not used as a feature
    language: str                  # python | javascript | java
    code: str
    cwes: list[str] = field(default_factory=list)
    is_vulnerable: bool = True     # False = the hard negative twin
    meta: dict = field(default_factory=dict)


def write_jsonl(records: Iterable[Record], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: Path) -> Iterator[Record]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield Record(**json.loads(line))
