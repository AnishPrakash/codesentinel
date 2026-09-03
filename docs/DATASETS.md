# Training data

The triage model is optional. Everything below is about making it *useful*, not
about making the tool work — delete `models/` and CodeSentinel is unchanged.

## What the model is for

It ranks. Given a file, it scores the thirteen deterministic classes, and those
scores are used for exactly two things:

1. ordering findings **within** a severity band, so the ones the model also
   recognises float up;
2. raising a **needs review** hint when it scores a class highly and no rule
   fired.

It never creates a finding and never names a CWE. A number measured here is a
ranking number. Presenting it as "CodeSentinel detects X% of vulnerabilities"
would be false, and the first judge who asks what the model outputs will find
out.

---

## The three sources

| Source | Cases | Language | Licence | Reachable without an account |
|---|---|---|---|---|
| [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) | 2,740 | Java | Apache-2.0 | Yes — `git clone` |
| [Juliet 1.3, Java](https://samate.nist.gov/SARD/test-suites/juliet) | ~28,000 | Java | Public domain | Yes — a ~50 MB zip |
| [CVEfixes](https://github.com/secureIT-project/CVEfixes) | ~5,000 methods | Python, JS, Java | CC BY 4.0 (data) | Dump on Zenodo, or build it yourself with a GitHub token |

### Which of these is worth trusting

**OWASP Benchmark and Juliet are generated.** Every case was written by a
program to exercise scanners. Their hard negatives are genuinely valuable — the
safe twin has the same imports, the same shape and the same category as the
vulnerable one, so a model cannot separate them on style. But a model that
scores well on them has learned *that generator's idioms*. It has not been shown
to generalise to code anyone shipped.

We measured this rather than assuming it. A model trained on OWASP Benchmark
alone scores **0.86 F1 on its own held-out test fold** for weak cryptography,
and then assigns near-zero to every finding in `demo/InvoiceController.java` —
a Spring controller, 15% of whose feature vector falls outside the range the
model ever saw. It is not broken. It is correctly saying it has no idea.

**CVEfixes is the one that answers the question.** It is built from real CVEs
and the commits that fixed them, storing each method before and after. The pair
is the whole point: same author, same file, same style, one difference. If you
run only one source, run this one.

---

## Running it

```bash
# 1. collect (each writes data/raw/*.jsonl)
python scripts/dataset/collect_owasp_benchmark.py --clone
python scripts/dataset/collect_juliet.py  --root  /path/to/juliet --limit 200   # smoke first
python scripts/dataset/collect_cvefixes.py --db   /path/to/CVEfixes.db --inspect
python scripts/dataset/collect_cvefixes.py --db   /path/to/CVEfixes.db --limit 200

# 2. features + labels -> data/processed/dataset.csv
python scripts/build_dataset.py

# 3. train, evaluate, export
python scripts/train_triage.py --epochs 300

# 4. verify on your machine
cs version                      # -> triage model: loaded
pytest -q                       # model-present tests now run instead of skipping
python scripts/benchmark.py     # the honest cost of the model
```

`notebooks/train_triage.ipynb` does the same on Kaggle, calling the same
scripts rather than re-implementing them in cells.

**Always run the collectors with `--limit` first.** Juliet and CVEfixes could
not be run against their real archives when they were written — `samate.nist.gov`
and `zenodo.org` were both unreachable from that environment. Their parsing is
covered by `tests/test_dataset_collectors.py` against fixtures built to each
source's documented shape, which catches a broken regex or a wrong column name
but cannot catch a schema that has moved. `--inspect` on the CVEfixes collector
prints the tables and columns your copy actually has; if they differ, the only
thing to edit is the `QUERY` constant.

---

## Methodology that the numbers depend on

**Split by group, never by row.** A vulnerable function and its own fixed twin
share a group. Split on rows and they land on opposite sides, the model sees the
answer at training time, and every metric jumps. This is the most common way a
vulnerability dataset lies to you, and `train_triage.py` asserts the groups are
disjoint rather than trusting the splitter.

Groups are: the repository for CVEfixes, the CWE directory for Juliet, and for
OWASP Benchmark a block of 100 consecutive ids **within a category**. That last
one is a judgement call worth stating — grouping on the category alone sends a
whole class to the test fold, so the model never trains on it and its recall is
zero by construction.

**Fit the scaler on the training fold only.** Fitting on everything leaks the
test distribution into the model's input range.

**Drop a sample rather than guess its label.** A CWE with no class in
`codesentinel/triage/labels.py` is dropped, not forced into the nearest one. A
mislabelled sample is worse than a missing one: it teaches the model that a real
vulnerability of one kind is evidence for another.

---

## The two refusals

Inference declines to answer in two situations, and both are deliberate.

**A language it was not trained on.** `feature_scaler.json` records the training
languages, and `TriageModel.predict` returns `None` for anything else. A model
trained only on Java has no basis for an opinion about Python, and emitting 0.02
is worse than emitting nothing — 0.02 is indistinguishable from a considered
judgement once it is printed next to a finding.

**A vector outside the training range.** Min-max scaling clamps silently, so
without a guard the model is asked about vectors it has never seen and answers
anyway. If more than 30% of features fall outside the range, it declines.

This is the same rule as everywhere else in the codebase, applied one level up:
*a probability is never allowed to become a claim.*

---

## Reading the report

`docs/model/test_report.csv`, one row per class:

- `status = untrained` — no positive sample existed. **Unmeasured, not zero.**
- `status = too few samples` — under 30 test positives. An F1 from that is noise.
- `support` — quote it next to any number you quote.

Say it like this: *"macro F1 0.77 across the three classes with at least 30
held-out samples, on OWASP Benchmark, group-split."* Not: *"F1 0.77."*

---

## What we actually measured

Reference run, OWASP Benchmark only, 2,615 rows over 271 groups, group-split:

| Class | Support | Precision | Recall | F1 | Status |
|---|---:|---:|---:|---:|---|
| CS002 SQL injection | 21 | 0.44 | 1.00 | 0.61 | too few samples |
| CS003 Command injection | 35 | 0.56 | 1.00 | 0.71 | ok |
| CS004 Weak cryptography | 88 | 0.83 | 0.90 | 0.86 | ok |
| CS007 XSS | 59 | 0.63 | 0.88 | 0.74 | ok |
| CS008 Path traversal | 24 | 0.48 | 0.92 | 0.63 | too few samples |
| CS009 Permissive config | 8 | 0.70 | 0.88 | 0.78 | too few samples |
| CS001, CS005, CS006, CS014–CS017 | 0 | — | — | — | **untrained** |

Macro F1 **0.772** over the three classes with ≥30 held-out samples.

Read what that says. Seven of thirteen classes have no data at all. Recall is
high and precision is middling, which is the right shape for a ranker — it
surfaces candidates rather than deciding — but it rests on a few dozen samples
per class from a generated corpus. **This is a working pipeline, not a
validated model.** Add Juliet and CVEfixes before quoting anything from it.
