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
  standard it encodes — CWE, OWASP and, with `--nist`, the SP 800-53 control.
  A probability is never allowed to become a claim.
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

**Tier 1 — deterministic (13).** A structural pattern is present in the tree.
Cited with a CWE, gated behind a comprehension question, counted in the exit code.

| ID | Class | CWE | OWASP | NIST | py | js | java |
|---|---|---|---|---|:-:|:-:|:-:|
| CS001 | Hardcoded credentials | CWE-798 | A07:2021 | IA-5 | ● | ● | ● |
| CS002 | SQL injection | CWE-89 | A03:2021 | SI-10 | ● | ● | ● |
| CS003 | Command injection | CWE-78 | A03:2021 | SI-10 | ● | ● | ● |
| CS004 | Weak cryptography | CWE-327 | A02:2021 | SC-13 | ● | ● | ● |
| CS005 | Missing route authentication | CWE-306 | A01:2021 | AC-3 | ● | ● | ● |
| CS006 | Unrecognised dependency | CWE-1104 | A06:2021 | SR-3 | ● | ● | – |
| CS007 | Cross-site scripting | CWE-79 | A03:2021 | SI-10 | ● | ● | – |
| CS008 | Path traversal | CWE-22 | A01:2021 | AC-3 | ● | ● | ● |
| CS009 | Overly permissive configuration | CWE-942 | A05:2021 | CM-6 | ● | ● | – |
| CS014 | Unsafe deserialization | CWE-502 | A08:2021 | SI-10 | ● | ● | ● |
| CS015 | Certificate validation disabled | CWE-295 | A02:2021 | SC-8 | ● | ● | ● |
| CS016 | Cleartext transmission | CWE-319 | A02:2021 | SC-8 | ● | ● | ● |
| CS017 | Sensitive data written to logs | CWE-532 | A09:2021 | AU-9 | ● | ● | ● |

**Tier 2 — advisory (4).** A heuristic about something *absent*.

| ID | Class | CWE | OWASP | NIST | py | js | java |
|---|---|---|---|---|:-:|:-:|:-:|
| CS010 | No CSRF protection visible | CWE-352 | A01:2021 | SC-23 | ● | ● | – |
| CS011 | No rate limit visible on an auth route | CWE-770 | A04:2021 | SC-5 | ● | ● | – |
| CS012 | Request data reaches a sink unvalidated | CWE-20 | A03:2021 | SI-10 | ● | ● | – |
| CS013 | Check-then-use race | CWE-367 | A04:2021 | SC-3 | ● | ● | – |

Python, JavaScript/TypeScript and Java. **Java coverage is a documented subset** —
run `cs rules --lang java` for exactly what applies to it, and see
`docs/DECISIONS.md` for why CS006 is absent there.

**This is not a security audit** — anything outside these seventeen classes was
not examined, and every result says so.

---

## Commands

```
cs scan <path>       find, explain, report   (exit 1 at or above --fail-on)
cs explain <rule>    what a class is, without scanning anything
cs learn <rule>      answer the question, unlock the fix
cs progress          what you have learned  (--reset to erase)
cs history           past scans on this machine
cs rules             what is checked   (--lang java, --nist)
cs install-hook      git pre-commit hook that scans staged files
cs install-model     optional triage model (the only network call in the tool)
cs version           version, and whether the model is loaded
```

`cs scan` flags: `--format text|json|markdown`, `--fail-on
critical|high|medium|low|none`, `--show-fix`, `--nist`, `--quiet`,
`--no-ledger`, `--no-recursive`.

### Git pre-commit hook

```bash
cs install-hook                 # in your repo
CS_FAIL_ON=high git commit      # raise or lower the bar for one commit
git commit --no-verify          # bypass, deliberately and visibly
```

It scans **only the staged content**, not the working tree — so what is checked
is what is committed, and a hook that takes ten seconds does not get disabled.
Advisories never block.

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
| `demo/deps_demo.py` | 14 | 2.8 ms | 3.1 ms |
| `demo/invoices.py` | 51 | 3.9 ms | 4.3 ms |
| `demo/orders.js` | 41 | 4.4 ms | 5.0 ms |
| `demo/InvoiceController.java` | 58 | 2.9 ms | 3.2 ms |
| 2 000-line file | 2001 | 196 ms | 218 ms |

(Slower than the first build: seventeen classes across three languages is more
work than nine across two. Still an order of magnitude inside the <30 ms budget
for a normal file.)

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

pytest -q                                    # 102 tests
ruff check .
cs scan codesentinel/ --fail-on critical     # dogfood

cd vscode-extension
npm install
npm run typecheck        # tsc --noEmit, strict
npm run bundle           # esbuild -> out/extension.js, one file
npm run package          # -> codesentinel-0.1.0.vsix
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
