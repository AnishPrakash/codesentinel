# Where this build differs from `plan.md`, and why

`plan.md` and the phased build guides were written at different times and
disagree in five places. Silently picking one would hide a real decision, so
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

## 2. Thirteen classes in two tiers, not twelve flat

**plan.md:** 12 flat vulnerability categories, all equal.
**Built:** 13 classes split into deterministic (9) and advisory (4).

Every one of plan.md's 12 is present. The build adds **command injection
(CWE-78)** — plan.md lists `os.system` / `shell=True` in its AST rules table but
not in the 12 output labels, which looked like an oversight rather than a
decision.

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

One CWE differs: plan.md cites **CWE-732** (Incorrect Permission Assignment) for
"Overly Broad Permissions". CS009 fires mostly on wildcard CORS and `debug=True`,
so it cites **CWE-942** (Permissive Cross-domain Policy). If the rule is ever
narrowed to filesystem permissions, CWE-732 becomes the right citation.

---

## 3. ONNX Runtime, not C++ with Eigen and pybind11

**plan.md:** hand-written NumPy CNN + self-attention, ported to C++ with Eigen,
exposed through pybind11, for "<30 ms and judges impressed by no ML framework".
**Built:** PyTorch → ONNX export, `onnxruntime` on CPU.

Three reasons:

- **The latency claim is already met without it.** Measured on this build:
  median **2.8 ms** for a 51-line file, **141 ms** for a 2 000-line file, rules
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

**`scanner.test.ts` is `scripts/verify-bridge.js`.** plan.md asks for a test that
"scanner correctly spawns CLI and parses JSON". Rather than mock the CLI inside
the VS Code test harness, `verify-bridge.js` spawns the real CLI exactly as
`scanner.ts` does and asserts every field the extension reads actually arrives —
including that credentials are redacted and that the comprehension gate reaches
the editor. It runs in CI. A mocked test would have passed even if the two sides
had drifted apart, which is the only failure worth catching here.

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
