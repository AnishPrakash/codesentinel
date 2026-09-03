# CodeSentinel for VS Code

Squiggles for security flaws, with an explanation you can read and a question you
have to answer before the fix appears.

## It is the same tool as the CLI

The extension contains **no detection logic**. It spawns

```
python -m codesentinel scan <file> --format json --no-ledger
```

and renders the result. That is deliberate: the CLI and the editor must never be
able to disagree about whether a file is safe, and the only way to guarantee
that is for exactly one of them to decide.

## Install

1. Install the CLI into an environment:

   ```bash
   conda activate code_env
   pip install -e /path/to/CodeSentinel
   ```

2. Build and load the extension:

   ```bash
   cd vscode-extension
   npm install
   npm run typecheck     # tsc --noEmit, strict mode
   npm run bundle        # esbuild -> out/extension.js, a single file
   ```

   Then press <kbd>F5</kbd> in VS Code to launch an Extension Development Host.

   To install it properly instead:

   ```bash
   npm run package                                  # -> codesentinel-0.1.0.vsix
   code --install-extension codesentinel-0.1.0.vsix
   ```

3. Point the extension at the right interpreter:

   ```jsonc
   // .vscode/settings.json
   { "codesentinel.pythonPath": "C:\\Users\\you\\miniconda3\\envs\\code_env\\python.exe" }
   ```

   On macOS/Linux: `~/miniconda3/envs/code_env/bin/python`.

## Languages

Python, JavaScript, TypeScript, JSX/TSX, and **Java**. Java coverage is a
documented subset — run `cs rules --lang java` to see exactly which classes
apply to it.

## What you get

| | |
|---|---|
| **Diagnostics** | Deterministic findings are Errors and Warnings. Advisories are Hints - a different squiggle, because "we could not see a rate limiter" is not the same claim as "this query concatenates user input". |
| **Sidebar** | Findings and Advisories in two separate groups, grouped by file. Click to jump. |
| **Status bar** | Finding count for the active file, or `clean`. |
| **Scan on save** | On by default. Set `codesentinel.scanOnSave` to `false` to disable. |
| **Severity filter** | `codesentinel.minSeverity` hides findings below a level. It does not apply to advisories — those are a different kind of claim, not a quieter one, so `showAdvisories` controls them. |
| **The gate** | Hover shows the explanation and the comprehension question, not the fix. Run **CodeSentinel: Answer the Comprehension Question** to unlock it. |

## Settings

| Setting | Default | What it does |
|---|---|---|
| `codesentinel.pythonPath` | `python` | Interpreter that has CodeSentinel installed |
| `codesentinel.scanOnSave` | `true` | Scan a supported file on every save |
| `codesentinel.showAdvisories` | `true` | Show advisory heuristics as Hints |
| `codesentinel.showFix` | `false` | Skip the gate and show fixes inline |
| `codesentinel.gutterIcons` | `true` | Highlight lines with findings |
| `codesentinel.minSeverity` | `low` | Lowest severity shown as a diagnostic |
| `codesentinel.timeoutMs` | `30000` | Give up on a scan after this long |

## Commands

- CodeSentinel: Scan This File
- CodeSentinel: Scan Workspace
- CodeSentinel: Clear Findings
- CodeSentinel: Answer the Comprehension Question
- CodeSentinel: Show Learning Progress
- CodeSentinel: Show Log

## Privacy

Editor scans pass `--no-ledger`, so scanning on save does not fill your local
history with noise. Answering a comprehension question does write to
`~/.codesentinel/ledger.db` - that is the point of it. Nothing leaves the machine
either way.
