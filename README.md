# CodeSentinel

**Local-first code security review with plain-language explanations.**

Finds security flaws in code with deterministic structural rules, explains each
one in ordinary language grounded in the CWE and OWASP entry it encodes, and
asks you a comprehension question before handing over the fix.

Ships as two things that share one brain: a **CLI** and a **VS Code extension**.
The extension contains no detection logic — it spawns the CLI and renders the
JSON. They cannot disagree about whether your code is safe, because only one of
them decides.

Built for Recursion Edition II (Microsoft Innovation Club, VIT Chennai),
Track 1 — PS3: Closing the Expertise Gap.

---

## Install

```bash
# with conda (the environment this project targets)
conda create -n code_env python=3.11 -y
conda activate code_env
pip install -e .

cs scan yourfile.py
```

Or straight from GitHub, no clone:

```bash
pip install "git+https://github.com/AnishPrakash/codesentinel.git"
# isolated, no virtualenv fuss:
pipx install "git+https://github.com/AnishPrakash/codesentinel.git"
```

Convenience scripts that do the conda setup and run the full verification:

```bash
./scripts/setup_env.sh        # macOS / Linux
scripts\setup_env.bat         # Windows
```

For the editor: [`vscode-extension/README.md`](vscode-extension/README.md).

---

## Why it is different

- **The detector cannot hallucinate.** Findings come from structural AST matches
  over a tree-sitter parse, so every alert cites the rule that fired and the
  standard it encodes. A probability is never allowed to become a claim.
- **It refuses to auto-fix.** You get the fix once you can explain the problem.
- **It says what it did not check.** Every result, including a clean one, prints
  the coverage statement. A green tick with no scope is a false sense of security.
- **It separates facts from guesses.** Deterministic findings and advisory
  heuristics are different tiers with different rendering, and only findings
  affect the exit code.
- **It remembers what you have learned.** Explain a class correctly once and it
  stops asking, and starts tracking. `cs progress`.
- **It never touches the network.** No account, no API key, no telemetry. The one
  exception is the opt-in `cs install-model`, which runs once.

---

## Coverage

**Tier 1 — deterministic.** A structural pattern is present in the tree. Cited
with a CWE, gated behind a comprehension question, counted in the exit code.

| ID | Class | CWE | OWASP |
|---|---|---|---|
| CS001 | Hardcoded credentials | CWE-798 | A07:2021 |
| CS002 | SQL injection | CWE-89 | A03:2021 |
| CS003 | Command injection | CWE-78 | A03:2021 |
| CS004 | Weak cryptography | CWE-327 | A02:2021 |
| CS005 | Missing route authentication | CWE-306 | A01:2021 |
| CS006 | Unrecognised dependency | CWE-1104 | A06:2021 |
| CS007 | Cross-site scripting | CWE-79 | A03:2021 |
| CS008 | Path traversal | CWE-22 | A01:2021 |
| CS009 | Overly permissive configuration | CWE-942 | A05:2021 |

**Tier 2 — advisory.** A heuristic about something *absent*. Absence is not
provable from one file, so these are never critical, never gated, never counted
in the exit code, and labelled advisory in every output.

| ID | Class | CWE | OWASP |
|---|---|---|---|
| CS010 | No CSRF protection visible | CWE-352 | A01:2021 |
| CS011 | No rate limit visible on an auth route | CWE-770 | A04:2021 |
| CS012 | Request data reaches a sink unvalidated | CWE-20 | A03:2021 |
| CS013 | Check-then-use race | CWE-367 | A04:2021 |

Python and JavaScript/TypeScript. **This is not a security audit** — anything
outside these thirteen classes was not examined.

---

## Commands

```
cs scan <path>       find, explain, report   (exit 1 at or above --fail-on)
cs explain <rule>    what a class is, without scanning anything
cs learn <rule>      answer the question, unlock the fix
cs progress          what you have learned  (--reset to erase)
cs history           past scans on this machine
cs rules             what is checked
cs install-model     optional triage model (the only network call in the tool)
cs version           version, and whether the model is loaded
```

`cs scan` flags: `--format text|json|markdown`, `--fail-on
critical|high|medium|low|none`, `--show-fix`, `--quiet`, `--no-ledger`,
`--no-recursive`.

Drop it into CI unchanged:

```yaml
- name: Security scan
  run: cs scan ./src --fail-on critical
```

---

## How it works

```
source ──▶ tree-sitter parse ──▶ rule engine  ──▶ findings (facts, with a CWE)
                     │                                    │
                     └──▶ 52-feature vector ──▶ triage ────┘  (ordering only)
                                                     └──▶ needs_review (opinion,
                                                          never named, never a CWE)
```

Rules decide findings; the optional neural model only orders them and flags
files where it predicts risk no rule covered. It never creates a `Finding` and
never names a CWE — enforced by a test that fails if severity ordering is ever
subordinated to model confidence.

The model is optional in the strongest sense: delete `models/` and everything
still works, which is asserted by `test_works_without_model`.

---

## Measured

Latency, measured on the machine this was built on (4-core cloud container,
Python 3.11, rules only, no triage model — `python scripts/benchmark.py`):

| File | Lines | Median | p95 |
|---|---|---|---|
| `demo/deps_demo.py` | 14 | 1.3 ms | 1.6 ms |
| `demo/invoices.py` | 51 | 2.8 ms | 3.2 ms |
| `demo/orders.js` | 41 | 3.8 ms | 4.1 ms |
| 2 000-line file | 2001 | 141 ms | 151 ms |

Re-run it on your demo machine and quote *those* numbers — latency is the
easiest claim in a pitch to check live.

False positives: the test suite includes a clean fixture that is structurally
identical to the vulnerable one — same routes, same imports, same shape — and
asserts it produces **zero** findings. Detection is easy; not firing on safe
code is the hard part.

The tool is also clean on its own source: `cs scan codesentinel/ --fail-on
critical` passes, and CI runs it on every push.

---

## Privacy

`~/.codesentinel/ledger.db` records which rules fired on which line of which
file, and which classes you have explained. **It contains no source code** —
asserted by a test that reads the raw database bytes and greps for the fixture's
credentials and queries. `cs scan --no-ledger` disables it; `cs progress
--reset` erases it. The VS Code extension always passes `--no-ledger` when
scanning on save.

---

## Development

```bash
pip install -r requirements-dev.txt
pip install -e .

pytest -q                                    # 57 tests
ruff check .
cs scan codesentinel/ --fail-on critical     # dogfood

cd vscode-extension && npm install && npm run compile
node scripts/verify-bridge.js python         # CLI/extension contract
```

`scripts/build_manifests.py` rebuilds the offline package manifests from the
live registries. It is run *before* shipping, never at scan time — resolving a
package name against a live registry is exactly what a slopsquatted package
wants you to do.

---

## Not built here

Two pieces are documented but deliberately not in this repo: the dataset
pipeline (`09-DATASETS.md`) and the Kaggle training notebook
(`10-KAGGLE-TRAINING.md`). The triage model they produce is optional; the tool
is complete without it.

---

## Licence

MIT.
