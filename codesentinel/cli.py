"""CodeSentinel - local-first code security review.

Runs entirely on this machine. No network calls, no API key, no telemetry.
The single exception is `cs install-model`, which is opt-in and runs once.
"""
from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from . import ledger
from .config import get_settings
from .explain import enrich
from .explain.grader import grade
from .explain.socratic import QUESTIONS
from .explain.templates import TEMPLATES, cwe_data
from .languages import detect_language
from .models import Language, ScanResult, Severity, Tier
from .parser import parse
from .rules.engine import COVERED, coverage_statement, run_rules
from .triage import triage

# Derived, never typed by hand. These help strings said "CS001..CS009" and
# "CS001..CS013" long after there were seventeen classes: a hardcoded count is
# a claim about coverage, and it goes stale the moment a rule is added.
_RULE_ID_HELP = (f"one of the {len(COVERED)} rule ids, "
                 f"{sorted(c[0] for c in COVERED)[0]}"
                 f"..{sorted(c[0] for c in COVERED)[-1]}")

app = typer.Typer(
    add_completion=False,
    help="Local-first code security review with plain-language explanations.",
    no_args_is_help=True,
)
console = Console()

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
             "dist", "build", ".next", ".mypy_cache", ".pytest_cache"}
EXTENSIONS = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java"}

SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
THRESHOLDS = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
              "medium": Severity.MEDIUM, "low": Severity.LOW}
LANG_ABBREV = {Language.PYTHON: "py", Language.JAVASCRIPT: "js", Language.JAVA: "java"}


# ------------------------------------------------------------------ helpers

def _syntax_lang(language: Language) -> str:
    """Pygments lexer name for a language, used for fix-snippet highlighting."""
    return {
        Language.PYTHON: "python",
        Language.JAVASCRIPT: "javascript",
        Language.JAVA: "java",
    }[language]


def _iter_files(target: Path, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target]
    pattern = "**/*" if recursive else "*"
    return sorted(
        p for p in target.glob(pattern)
        if p.is_file() and p.suffix in EXTENSIONS
        and not any(part in SKIP_DIRS for part in p.parts)
    )


def _scan_one(path: Path) -> ScanResult | None:
    settings = get_settings()
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > settings.max_file_bytes:
        console.print(f"[dim]skipped {path} (larger than "
                      f"{settings.max_file_bytes // 1000} KB)[/dim]")
        return None
    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if code.count("\n") > settings.max_lines:
        console.print(f"[dim]skipped {path} (over {settings.max_lines} lines)[/dim]")
        return None

    language = detect_language(path.name, code)
    t0 = time.perf_counter()
    parsed = parse(code, language)
    findings, prediction = triage(
        parsed, enrich(run_rules(parsed, local_root=path.parent)))
    elapsed = (time.perf_counter() - t0) * 1000

    return ScanResult(
        path=str(path), language=language, line_count=code.count("\n") + 1,
        elapsed_ms=elapsed, findings=findings, prediction=prediction,
    )


# ------------------------------------------------------------------ render

def _render_file(result: ScanResult, show_fix: bool) -> None:
    if not result.findings and result.prediction is None:
        return
    console.print(f"\n[bold]{result.path}[/bold]")

    findings = [f for f in result.findings if f.tier is Tier.DETERMINISTIC]
    advisories = [f for f in result.findings if f.tier is Tier.ADVISORY]

    for f in findings:
        style = SEV_STYLE[f.severity]
        # The model's score is deliberately NOT printed beside a finding. It
        # measures how much this file resembles the training corpus, and it is
        # used only to order findings within a severity band. Printing "0.00"
        # next to a CRITICAL reads as "the tool is 0% sure this is real", which
        # is the exact misreading the two-tier design exists to prevent - the
        # rule is certain, and the model was asked a different question. The
        # score stays in --format json, where it is data rather than a claim,
        # and the model speaks for itself in the needs-review panel below.
        console.print(
            f"  [{style}]{f.severity.label.upper():8s}[/{style}] "
            f"[bold]{f.title}[/bold]\n"
            f"           [dim]line {f.line} | {f.rule_id} | {f.cwe} | "
            f"{f.owasp.split('-')[0].strip()}[/dim]"
        )
        console.print(f"           [dim]{f.snippet}[/dim]")
        console.print(f"           {f.explanation}", highlight=False)
        if f.attack:
            console.print(f"           [italic]{f.attack}[/italic]", highlight=False)

        if f.question and not show_fix:
            console.print(f"           [yellow]Before the fix:[/yellow] {f.question}")
            console.print(f"           [dim]run:  cs learn {f.rule_id}[/dim]")
        elif f.fix:
            lang = _syntax_lang(result.language)
            console.print(Panel(
                Syntax(f.fix, lang, theme="ansi_dark", word_wrap=True),
                border_style="green", box=box.ROUNDED, padding=(0, 1)))
        console.print()

    if advisories:
        console.print("  [yellow]ADVISORY[/yellow] [dim]- heuristics, not findings. "
                      "These are prompts to check, and may be handled elsewhere in "
                      "your stack.[/dim]")
        for f in advisories:
            console.print(f"           [dim]line {f.line} | {f.rule_id} | {f.cwe}[/dim]  "
                          f"{f.title}")
            console.print(f"           [dim]{f.explanation.splitlines()[0]}[/dim]")
        console.print()

    if result.prediction is not None:
        console.print(Panel(
            f"[yellow]needs review[/yellow]  (model score "
            f"{result.prediction.score:.2f})\n{result.prediction.note}",
            border_style="yellow", box=box.ROUNDED, padding=(0, 1)))
        console.print()


def _summary(results: list[ScanResult], n_files: int, elapsed_ms: float) -> None:
    counts: dict[Severity, int] = {}
    n_advisory = 0
    for r in results:
        for f in r.findings:
            if f.tier is Tier.ADVISORY:
                n_advisory += 1
                continue
            counts[f.severity] = counts.get(f.severity, 0) + 1

    if counts:
        parts = [f"[{SEV_STYLE[s]}]{counts[s]} {s.label}[/{SEV_STYLE[s]}]"
                 for s in sorted(counts, reverse=True)]
        console.print("  " + "   ".join(parts))
    else:
        console.print("  [green]No findings.[/green]")

    total = sum(1 for r in results for f in r.findings
                if f.tier is Tier.DETERMINISTIC)
    advisory_note = f" | {n_advisory} advisory" if n_advisory else ""
    console.print(f"[dim]{n_files} file(s) in {elapsed_ms:.0f} ms | "
                  f"{total} finding(s){advisory_note}[/dim]")
    console.print(f"[dim]{coverage_statement()}[/dim]\n")


def _markdown(results: list[ScanResult], n_files: int, elapsed_ms: float) -> str:
    out = ["# CodeSentinel report", ""]
    total = sum(len(r.findings) for r in results)
    out += [f"{n_files} file(s) scanned in {elapsed_ms:.0f} ms - {total} finding(s).", ""]
    for r in results:
        if not r.findings:
            continue
        out.append(f"## `{r.path}`")
        for f in r.findings:
            lang = _syntax_lang(r.language)
            tier = "" if f.tier is Tier.DETERMINISTIC else " *(advisory)*"
            out += [
                f"### {f.severity.label}: {f.title} (line {f.line}){tier}",
                f"`{f.rule_id}` | {f.cwe} | {f.owasp}", "",
                "```", f.snippet, "```", "",
                f.explanation, "", f"**Attack.** {f.attack}", "",
                "**Fix.**", "", f"```{lang}", f.fix, "```", "",
            ]
    out += ["---", "", coverage_statement()]
    return "\n".join(out)


# ----------------------------------------------------------------- commands

@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, help="File or directory to scan."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", "-r"),
    fmt: str = typer.Option("text", "--format", "-f", help="text | json | markdown"),
    show_fix: bool = typer.Option(
        False, "--show-fix", help="Print fixes without the comprehension check."),
    fail_on: str = typer.Option(
        "critical", "--fail-on",
        help="Exit 1 at or above this severity: critical|high|medium|low|none"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Summary only."),
    no_ledger: bool = typer.Option(False, "--no-ledger",
                                   help="Do not read or write the local ledger."),
    nist: bool = typer.Option(False, "--nist",
                              help="Also cite the NIST SP 800-53 control each class "
                                   "relates to."),
) -> None:
    """Scan a file or directory for security flaws."""
    from .explain import templates
    from .triage.model import get_model

    templates.set_nist(nist)

    t0 = time.perf_counter()
    files = _iter_files(target, recursive)
    if not files:
        console.print("[yellow]No supported files found.[/yellow] "
                      "(.py .js .jsx .mjs .cjs .ts .tsx .java)")
        raise typer.Exit(0)

    known = set() if no_ledger else ledger.mastered_rules()

    results: list[ScanResult] = []
    for path in files:
        r = _scan_one(path)
        if r is None:
            continue
        if known:
            # already explained this class - do not gate them again
            r.findings = [
                dataclasses.replace(f, question="") if f.rule_id in known else f
                for f in r.findings
            ]
        if not no_ledger:
            ledger.record_scan(r, model_used=get_model().ready)
        results.append(r)

    elapsed = (time.perf_counter() - t0) * 1000

    if fmt == "json":
        console.print_json(json.dumps({
            "files": [{
                "path": r.path, "language": r.language.value,
                "lines": r.line_count, "elapsed_ms": round(r.elapsed_ms, 2),
                "findings": [f.to_dict() for f in r.findings],
                "needs_review": (
                    {"score": r.prediction.score, "note": r.prediction.note}
                    if r.prediction else None),
            } for r in results],
            "coverage": coverage_statement(),
            "stats": {"files": len(files),
                      "findings": sum(len(r.findings) for r in results),
                      "elapsed_ms": round(elapsed, 2)},
        }))
    elif fmt == "markdown":
        print(_markdown(results, len(files), elapsed))
    else:
        if not quiet:
            for r in results:
                _render_file(r, show_fix)
        _summary(results, len(files), elapsed)
        if known:
            console.print(f"[dim]Not re-asking about {', '.join(sorted(known))} - "
                          f"you have explained "
                          f"{'that' if len(known) == 1 else 'those'} already.[/dim]\n")

    # Advisories never affect the exit code. A CI job must not fail because we
    # could not see a rate limiter that lives in the ingress config.
    if fail_on != "none":
        gate = THRESHOLDS.get(fail_on, Severity.CRITICAL)
        if any(f.severity >= gate for r in results for f in r.findings
               if f.tier is Tier.DETERMINISTIC):
            raise typer.Exit(1)


@app.command()
def explain(rule_id: str = typer.Argument(..., help=_RULE_ID_HELP)) -> None:
    """Explain one rule class without scanning anything."""
    rid = rule_id.upper()
    tpl = TEMPLATES.get(rid)
    meta = next((c for c in COVERED if c[0] == rid), None)
    if not tpl or not meta:
        console.print(f"[red]Unknown rule {rule_id!r}.[/red]  Try:  cs rules")
        raise typer.Exit(1)

    cwe = cwe_data().get(meta[2], {})
    tier_note = ("" if meta[4] == "deterministic"
                 else "\n\n[yellow]This is an advisory[/yellow] - a heuristic about "
                      "something absent. It is never gated and never fails a build.")
    console.print(Panel(
        f"[bold]{meta[1]}[/bold]\n[dim]{meta[2]} - {cwe.get('name', '')}[/dim]\n\n"
        f"{cwe.get('summary', '')}\n\n"
        f"[bold]Why it matters[/bold]\n{tpl['why']}\n\n"
        f"[bold]What an attacker does[/bold]\n{tpl['attack']}{tier_note}",
        border_style="cyan", box=box.ROUNDED, padding=(1, 2)))
    console.print(Panel(
        Syntax(tpl["fix_python"], "python", theme="ansi_dark", word_wrap=True),
        title="Fix (Python)", border_style="green", box=box.ROUNDED))
    console.print(Panel(
        Syntax(tpl["fix_javascript"], "javascript", theme="ansi_dark", word_wrap=True),
        title="Fix (JavaScript)", border_style="green", box=box.ROUNDED))
    if q := QUESTIONS.get(rid):
        console.print(f"\n[yellow]Comprehension check:[/yellow] {q}")
        console.print(f"[dim]run:  cs learn {rid}[/dim]\n")


@app.command()
def learn(rule_id: str = typer.Argument(..., help=_RULE_ID_HELP)) -> None:
    """Answer the comprehension question and unlock the fix."""
    rid = rule_id.upper()
    question = QUESTIONS.get(rid)
    if not question:
        console.print(f"[red]No comprehension check for {rid}.[/red]")
        raise typer.Exit(1)

    console.print(Panel(question, title=f"{rid} - in your own words",
                        border_style="yellow", box=box.ROUNDED, padding=(1, 2)))

    for attempt in range(1, 4):
        answer = typer.prompt("\nYour answer")
        passed, feedback, _ = grade(rid, answer)
        ledger.record_attempt(rid, passed)
        if passed:
            console.print(f"\n[green]{feedback}[/green]\n")
            console.print(Panel(
                Syntax(TEMPLATES[rid]["fix_python"], "python",
                       theme="ansi_dark", word_wrap=True),
                title="Fix", border_style="green", box=box.ROUNDED))
            raise typer.Exit(0)
        console.print(f"[yellow]{feedback}[/yellow]")
        if attempt == 3:
            console.print("\n[dim]Here is the explanation - read it, then run "
                          f"`cs learn {rid}` again.[/dim]\n")
            console.print(TEMPLATES[rid]["why"])
            raise typer.Exit(1)


@app.command()
def rules(
    lang: str = typer.Option(
        "", "--lang", "-l",
        help="Show coverage for one language: python | javascript | java"),
    nist: bool = typer.Option(False, "--nist", help="Also show the NIST SP 800-53 control."),
) -> None:
    """List what CodeSentinel checks.

    Coverage is not identical across languages, so --lang prints the real subset
    rather than letting the full table imply parity.
    """
    from .explain.templates import nist_data
    from .rules.engine import rules_for

    language = None
    if lang:
        try:
            language = Language(lang.lower())
        except ValueError:
            console.print(f"[red]Unknown language {lang!r}.[/red]  "
                          "Try: python, javascript, java")
            raise typer.Exit(1) from None

    supported = set(rules_for(language)) if language else None

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("ID", style="bold")
    table.add_column("Class")
    table.add_column("CWE", style="dim")
    table.add_column("OWASP", style="dim")
    if nist:
        table.add_column("NIST", style="dim")
    table.add_column("Tier")
    if supported is None:
        table.add_column("Languages", style="dim")

    for rid, name, cwe, owasp, tier in COVERED:
        if supported is not None and rid not in supported:
            continue
        mark = ("[green]finding[/green]" if tier == "deterministic"
                else "[yellow]advisory[/yellow]")
        row = [rid, name, cwe, owasp]
        if nist:
            row.append(nist_data().get(rid, {}).get("control", "-"))
        row.append(mark)
        if supported is None:
            langs = [LANG_ABBREV[ln] for ln in Language if rid in set(rules_for(ln))]
            row.append(" ".join(langs) or "-")
        table.add_row(*row)

    console.print(table)
    if supported is None:
        console.print("[dim]py = Python, js = JavaScript/TypeScript, java = Java. "
                      "Java coverage is a subset - run  cs rules --lang java  "
                      "for exactly what applies.[/dim]")
    console.print(f"[dim]{coverage_statement(language)}[/dim]")


@app.command()
def progress(
    reset: bool = typer.Option(False, "--reset", help="Wipe the local ledger."),
) -> None:
    """What you have learned so far."""
    if reset:
        if typer.confirm("Erase all scan history and comprehension progress?"):
            console.print("[green]Ledger cleared.[/green]" if ledger.reset()
                          else "[red]Could not clear the ledger.[/red]")
        raise typer.Exit(0)

    rows = ledger.progress()
    mastered = sum(1 for r in rows if r["mastered"])

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("", width=3)
    table.add_column("Class")
    table.add_column("CWE", style="dim")
    table.add_column("Attempts", justify="right", style="dim")
    for r in rows:
        mark = "[green]ok[/green]" if r["mastered"] else "[dim].[/dim]"
        style = "" if r["mastered"] else "dim"
        table.add_row(mark, f"[{style}]{r['name']}[/{style}]" if style else r["name"],
                      r["cwe"], str(r["attempts"]))
    console.print(table)

    bar = "#" * mastered + "-" * (len(rows) - mastered)
    console.print(f"\n  [green]{bar}[/green]  "
                  f"[bold]{mastered} of {len(rows)}[/bold] classes explained\n")

    if mastered < len(rows):
        nxt = next(r for r in rows if not r["mastered"])
        console.print(f"[dim]Next:  cs learn {nxt['rule_id']}[/dim]\n")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """Recent scans from this machine."""
    rows = ledger.history(limit)
    if not rows:
        console.print("[yellow]No scans recorded yet.[/yellow]  Run:  cs scan .")
        raise typer.Exit(0)

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("When", style="dim", width=17)
    table.add_column("File", overflow="fold")
    table.add_column("Lines", justify="right", style="dim")
    table.add_column("Findings", justify="right")
    table.add_column("Worst")
    for r in rows:
        sev = Severity(r["worst"])
        worst = (f"[{SEV_STYLE[sev]}]{sev.label}[/{SEV_STYLE[sev]}]"
                 if r["finding_count"] else "[green]clean[/green]")
        table.add_row(r["created_at"][:16], r["path"], str(r["line_count"]),
                      str(r["finding_count"]), worst)
    console.print(table)
    console.print(f"[dim]Ledger: {get_settings().ledger_path}[/dim]")


@app.command("install-hook")
def install_hook(
    repo: Path = typer.Option(Path("."), "--repo", help="Repository to install into."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing hook."),
    fail_on: str = typer.Option("critical", "--fail-on",
                                help="Severity that blocks a commit."),
) -> None:
    """Install a git pre-commit hook that scans staged files.

    Scans only what is staged, so it stays fast, and blocks on deterministic
    findings only - a commit must never be blocked because we could not see a
    rate limiter that lives in the ingress config.
    """
    import shutil
    import stat

    hooks = repo.resolve() / ".git" / "hooks"
    if not hooks.parent.exists():
        console.print(f"[red]{repo.resolve()} is not a git repository.[/red]")
        raise typer.Exit(1)
    hooks.mkdir(parents=True, exist_ok=True)

    dest = hooks / "pre-commit"
    if dest.exists() and not force:
        console.print(f"[yellow]{dest} already exists.[/yellow]  "
                      "Re-run with --force to replace it.")
        raise typer.Exit(1)

    source = Path(__file__).resolve().parent.parent / "scripts" / "pre-commit"
    if not source.exists():
        console.print("[red]Hook template not found.[/red] "
                      "Install from a source checkout, not a wheel.")
        raise typer.Exit(1)

    shutil.copyfile(source, dest)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    console.print(f"[green]Installed[/green] {dest}")
    console.print(f"[dim]Blocks on: {fail_on} and above (set CS_FAIL_ON to change). "
                  "Bypass once with: git commit --no-verify[/dim]")
    if fail_on != "critical":
        console.print(f"[dim]Tip: export CS_FAIL_ON={fail_on} in your shell profile "
                      "to make that the default.[/dim]")


@app.command("install-model")
def install_model(
    tag: str = typer.Option("model-v1", "--tag"),
    repo: str = typer.Option("AnishPrakash/codesentinel", "--repo"),
) -> None:
    """Download the optional triage model (~2 MB). Scans work without it."""
    import urllib.request

    from .config import MODEL_DIR

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    base = f"https://github.com/{repo}/releases/download/{tag}"
    for name in ("triage.onnx", "feature_scaler.json"):
        dest = MODEL_DIR / name
        try:
            console.print(f"[dim]fetching {name}...[/dim]")
            urllib.request.urlretrieve(f"{base}/{name}", dest)      # noqa: S310
        except Exception as exc:                                    # noqa: BLE001
            console.print(f"[yellow]Could not fetch {name}: {exc}[/yellow]")
            console.print("[dim]CodeSentinel works without it - "
                          "you lose ranking and the needs-review signal.[/dim]")
            raise typer.Exit(1) from None
    console.print("[green]Model installed.[/green]  Run:  cs version")


@app.command()
def version() -> None:
    """Print the version."""
    from . import __version__
    from .triage.model import get_model
    console.print(f"codesentinel {__version__}")
    console.print(f"[dim]triage model: "
                  f"{'loaded' if get_model().ready else 'not installed'}[/dim]")


if __name__ == "__main__":
    app()
