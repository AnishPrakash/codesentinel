"""Measure end-to-end scan latency. Prints numbers you can quote."""
from __future__ import annotations

import statistics
import tempfile
import time
from pathlib import Path

from codesentinel.explain import enrich
from codesentinel.languages import detect_language
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules
from codesentinel.triage import triage
from codesentinel.triage.model import get_model


def bench(path: Path, n: int = 200) -> None:
    code = path.read_text(encoding="utf-8")
    lang = detect_language(path.name, code)
    parse(code, lang)                                   # warm caches

    timings = []
    for _ in range(n):
        t0 = time.perf_counter()
        ps = parse(code, lang)
        triage(ps, enrich(run_rules(ps)))
        timings.append((time.perf_counter() - t0) * 1000)

    timings.sort()
    print(f"{path.name:24s} {code.count(chr(10)) + 1:>5} lines   "
          f"median {statistics.median(timings):6.2f} ms   "
          f"p95 {timings[int(0.95 * len(timings))]:6.2f} ms   "
          f"max {timings[-1]:6.2f} ms")


if __name__ == "__main__":
    print(f"triage model: {'loaded' if get_model().ready else 'not installed'}\n")
    demo = Path(__file__).resolve().parent.parent / "demo"
    for p in (sorted(demo.glob("*.py")) + sorted(demo.glob("*.js"))
              + sorted(demo.glob("*.java"))):
        bench(p)
    # tempfile, not "/tmp": on Windows a hardcoded POSIX path resolves to
    # \tmp\ on the current drive, which does not exist.
    big_src = (demo / "invoices.py").read_text(encoding="utf-8")
    big = Path(tempfile.gettempdir()) / "cs_big.py"
    big.write_text(big_src * 40, encoding="utf-8")
    try:
        bench(big, n=50)
    finally:
        big.unlink(missing_ok=True)
