# Where this build differs from `plan.md`, and why

`plan.md` and the phased build guides were written at different times and
disagree in several places. Silently picking one would hide a real decision, so
each is recorded here with the reasoning and what it would cost to switch back.

None of these changes what the tool *detects* — they are all implementation
choices behind the same behaviour.

---

## 1. Typer, not Click

**plan.md:** `click` as the CLI framework.
**Built:** `typer`, which is a thin layer *over* Click.

Typer derives the parser from type hints, so `--fail-on critical|high|...` and
`--format text|json|markdown` are declared once instead of twice. It brings
Click along as a dependency, so anything Click can do is still reachable.

**Cost to switch:** `cli.py` only. Around 200 lines, half a day. Nothing else in
the codebase imports either library.

---

## 2. Seventeen classes in two tiers, not twelve flat

**plan.md:** 12 flat vulnerability categories, all equal.
**Built:** 17 classes split into deterministic (13) and advisory (4).

Every one of plan.md's 12 is present. The build adds five more, all of them
drawn from plan.md's own pattern-feature table (§"18 Pattern-Based Features"),
which listed detections that never made it into the 12 output labels:

| Added | CWE | From plan.md |
|---|---|---|
| CS003 Command injection | CWE-78 | feature 12, `os.system` / `shell=True` |
| CS014 Unsafe deserialization | CWE-502 | feature 18, `pickle.loads` / `marshal.loads` |
| CS015 Certificate validation disabled | CWE-295 | feature 9, `verify=False` |
| CS016 Cleartext transmission | CWE-319 | feature 14, `http://` not `https://` |
| CS017 Sensitive data written to logs | CWE-532 | feature 13, `print(password)` |

Three more of plan.md's pattern features were folded into classes that already
existed rather than given ids of their own: weak ciphers (DES/RC4/Blowfish/ECB)
into **CS004**, Google API keys and commented-out credentials into **CS001**,
and `tempfile.mktemp()` into **CS013** — mktemp is literally a check-then-use
race, so a second id for it would have been the same CWE twice.

The tier split is the substantive change. Four of plan.md's categories —
missing CSRF, missing rate limiting, missing input validation, TOCTOU — are
claims about something *absent*, and absence is not provable from one file. A
rate limiter can live in the ingress config; CSRF may not apply to a bearer-token
API at all. Reporting those with the same confidence as "this query concatenates
user input" is how a scanner's false-positive rate becomes meaningless, and the
false-positive number is the most valuable thing this project can publish.

So advisories are never critical, never gated behind a comprehension question,
never counted in the exit code, and rendered differently in every output — Hints
rather than Errors in the editor, a separate section in the terminal, a separate
group in the sidebar.

| plan.md index | plan.md category | Built as | Tier |
|---|---|---|---|
| 0 | Hardcoded Secrets | CS001 | deterministic |
| 1 | SQL Injection | CS002 | deterministic |
| 2 | Missing Authentication | CS005 | deterministic |
| 3 | Cross-Site Scripting | CS007 | deterministic |
| 4 | Insecure File Operations (CWE-22) | CS008 | deterministic |
| 5 | Missing Input Validation (CWE-20) | CS012 | **advisory** |
| 6 | Weak Cryptography | CS004 | deterministic |
| 7 | Missing CSRF Protection | CS010 | **advisory** |
| 8 | Overly Broad Permissions | CS009 | deterministic |
| 9 | Race Conditions (TOCTOU) | CS013 | **advisory** |
| 10 | Missing Rate Limiting | CS011 | **advisory** |
| 11 | Insecure Dependencies | CS006 | deterministic |
| — | *(command injection, CWE-78)* | CS003 | deterministic |
| — | *(unsafe deserialization, CWE-502)* | CS014 | deterministic |
| — | *(certificate validation off, CWE-295)* | CS015 | deterministic |
| — | *(cleartext transmission, CWE-319)* | CS016 | deterministic |
| — | *(sensitive data in logs, CWE-532)* | CS017 | deterministic |

One CWE differs: plan.md cites **CWE-732** (Incorrect Permission Assignment) for
"Overly Broad Permissions". CS009 fires mostly on wildcard CORS and `debug=True`,
so it cites **CWE-942** (Permissive Cross-domain Policy). If the rule is ever
narrowed to filesystem permissions, CWE-732 becomes the right citation.

---

## 2b. Java is built, and its coverage is a documented subset

**plan.md:** Java in the supported-languages list and the activation events.
**Built:** Java parsing plus 10 of the 17 classes.

Java is real, not a claim: `tree_sitter_java` is a dependency, `Language.JAVA`
runs end to end, and `tests/test_java.py` pins a vulnerable Spring controller
against a structurally identical safe one — 10 findings against **zero**.

What is absent, and why:

- **CS006 (unrecognised dependency).** Java resolves dependencies through Maven
  and Gradle *coordinates*, not import names. An import-name manifest would say
  nothing useful about `com.example.thing`, so the rule does not run rather than
  guessing. A real Java firewall reads `pom.xml` / `build.gradle`, which is a
  different feature.
- **CS007, CS009, CS010–CS013.** These are framework-shaped: they encode Flask,
  FastAPI and Express idioms. The Spring and Jakarta equivalents are a day of
  work each and none of them were written, so they are simply not registered for
  Java.

`cs rules --lang java` prints the real subset. That command exists precisely so
the full table can never be mistaken for parity — an unclaimed gap is fine, a
claimed one is not.

---

## 3. ONNX Runtime, not C++ with Eigen and pybind11

**plan.md:** hand-written NumPy CNN + self-attention, ported to C++ with Eigen,
exposed through pybind11, for "<30 ms and judges impressed by no ML framework".
**Built:** PyTorch → ONNX export, `onnxruntime` on CPU.

Three reasons:

- **The latency claim is already met without it.** Measured on this build:
  median **3.9 ms** for a 51-line file, **196 ms** for a 2 000-line file, rules
  only. The budget plan.md was optimising for is not under pressure.
- **A C++ extension is the single most likely thing to break on a demo machine.**
  It needs a compiler, CMake, matching Python headers and an ABI-compatible
  wheel per platform. `onnxruntime` is a pip install on all three.
- **Android was the original reason for a portable C++ core, and Android is out
  of scope.** The reason outlived the requirement.

The seam is preserved: `triage/model.py` loads the model and every failure path
returns `None`. Swapping in a pybind11 module means reimplementing one method,
`TriageModel.predict`. Nothing else changes.

---

## 4. One 52-feature specification, not two

`plan.md` and `02-PHASE-1-parser-features.md` both define 52 features, and they
are not the same 52. The build uses the phase-1 list because it was written
against tree-sitter and was executed and verified against the fixtures before
anything depended on it.

One consequence worth stating: adding Java did **not** add a 53rd feature.
`lang_is_python` and `lang_is_javascript` are a k-1 dummy encoding, so Java is
(0, 0) — the same information in the same 52 columns, and the contract with any
future model survives.

`FEATURE_NAMES` is the contract with the trained model. Appending is safe;
reordering is not. `FEATURE_VERSION` and the full name list are written into
`feature_scaler.json` at training time, and `TriageModel._load` **refuses to
load** on a mismatch rather than scoring a vector it does not recognise — a
silent reorder produces plausible wrong scores, which is worse than an error.

---

## 5. Flat package layout, not `backend/` + `cli/` + `model/`

**plan.md:** `backend/`, `cli/`, `model/`, `vscode-extension/` as siblings.
**Built:** one importable package, `codesentinel/`, plus `vscode-extension/`.

The split in plan.md assumed a web backend and a CLI as separate consumers of a
shared core. There is no web backend now, and `pip install` wants exactly one
package. A `cli/` directory separate from the library it calls would mean two
`__init__.py` trees, an editable install that only half works, and a console
script whose imports depend on the working directory.

Everything plan.md put in `backend/` is a module inside `codesentinel/`:
`parser.py`, `features/`, `rules/`, `explain/`, `triage/`, `ledger/`, `cli.py`.

The extension's own file layout follows plan.md exactly — `extension.ts`,
`scanner.ts`, `diagnostics.ts`, `decorations.ts`, `sidebar/`, `commands/`,
`utils/`.

---

## Two smaller ones

**The sidebar is a TreeView, not a webview.** plan.md specifies
`SidebarProvider.ts` as a `WebviewViewProvider` with `panel.html`. A TreeView is
native, themes itself, needs no CSP, and gives click-to-jump for free. The
webview is the right call only when the panel needs custom layout, which it does
not yet.

**NIST grounding is present but opt-in.** plan.md says explanations are
"grounded in OWASP/CWE/NIST". CWE and OWASP are quoted verbatim in every
explanation. NIST SP 800-53 is mapped for all 17 classes in
`data/grounding/nist.json` but printed only behind `cs scan --nist` and
`cs rules --nist`, because the control text is long and organisational and would
bury the part the user needs. The mapping is worded "relates to" rather than
"satisfies": SP 800-53 controls are system-level, so a line of code is evidence
toward a control, never satisfaction of one. Overclaiming that is the kind of
thing a compliance-literate judge catches immediately.

**The sidebar is a TreeView, not a webview.** plan.md asks for a test that
"scanner correctly spawns CLI and parses JSON". Rather than mock the CLI inside
the VS Code test harness, `verify-bridge.js` spawns the real CLI exactly as
`scanner.ts` does and asserts every field the extension reads actually arrives —
including that credentials are redacted and that the comprehension gate reaches
the editor. It runs in CI. A mocked test would have passed even if the two sides
had drifted apart, which is the only failure worth catching here.

---

## Precision work, and what it cost

Four rules were narrowed after being run against CodeSentinel's own source,
where they produced false positives:

- **CS016** fired on our own explanation template, which contains the sentence
  "http:// is unencrypted". A URL inside prose is not a request target, so the
  pattern is now anchored to the whole literal and rejects internal whitespace.
- **CS017** fired on `console.print("...password...")` — a message that mentions
  a credential is not a leak. It now inspects the *identifiers* passed to the
  call, ignoring string literals, and understands f-string interpolation.
- **CS016's** name heuristic had the `\b` bug for the second time in this
  project: `REPORT_ENDPOINT` has word characters either side of "endpoint", so a
  `\b`-anchored pattern never fires. There is now a named test for exactly that
  trap, because it has shipped twice.
- **CS006** flagged our own `tree_sitter_java` import, which is a real package
  that was missing from the curated manifest.

`test_codesentinel_is_clean_on_its_own_source` now runs the whole rule set over
the whole package in CI. Dogfooding as a test rather than as a habit.

A fifth, found later and worse than the other four: **CS006 flagged `import
yaml`**. A manifest lists what a registry publishes (`pyyaml`); code writes what
it imports (`yaml`). Hyphen and underscore normalisation bridges
`tree_sitter_java` to `tree-sitter-java` and nothing else, so `cv2`, `sklearn`,
`bs4`, `jwt`, `PIL`, `dateutil` and eleven more of the most common imports in
Python were all reported as possible slopsquats. `codesentinel/deps/aliases.py`
is now the single table both the firewall and the manifest builder read, so the
two cannot drift, and a self-consistency test rejects an alias pointing at a
distribution the manifest does not contain.

---

## What is not built

Two things from the guides, excluded deliberately and not stubbed:

- **The dataset pipeline** (`09-DATASETS.md`)
- **The Kaggle training notebook** (`10-KAGGLE-TRAINING.md`)

They produce `models/triage.onnx` and `models/feature_scaler.json`. The tool is
complete without them — `test_works_without_model` asserts a scan is unaffected
by their absence, and `cs version` reports `triage model: not installed` rather
than failing.

Any accuracy figure for the model — plan.md quotes F1 0.87 and 112,400 samples —
is a **target**, not a measurement, until that notebook has been run. Nothing in
this repo produces those numbers, and nothing in the README claims them.
