import * as vscode from 'vscode';

import { Finding, ScanReport } from './scanner';
import { getSettings } from './utils/config';

/**
 * Turns findings into vscode.Diagnostic objects.
 *
 * The tier mapping is the whole ethical design of this extension in three lines:
 * a deterministic finding is an Error or Warning because a pattern is provably
 * present; an advisory is a Hint because it is a guess about something absent.
 * A squiggle that means "we could not see a rate limiter" must not look the same
 * as one that means "this query concatenates user input".
 */

export const COLLECTION_NAME = 'codesentinel';

function severityFor(f: Finding): vscode.DiagnosticSeverity {
  if (f.tier === 'advisory') {
    return vscode.DiagnosticSeverity.Hint;
  }
  switch (f.severity) {
    case 4:
      return vscode.DiagnosticSeverity.Error;
    case 3:
      return vscode.DiagnosticSeverity.Warning;
    case 2:
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function rangeFor(f: Finding, document?: vscode.TextDocument): vscode.Range {
  const startLine = Math.max(0, f.line - 1);
  const endLine = Math.max(startLine, f.end_line - 1);
  if (document && startLine < document.lineCount) {
    const start = new vscode.Position(startLine, f.column);
    const lastLine = Math.min(endLine, document.lineCount - 1);
    const end = document.lineAt(lastLine).range.end;
    return new vscode.Range(start, end);
  }
  return new vscode.Range(startLine, f.column, endLine, f.column + 1);
}

/**
 * The message the user reads on hover. When the comprehension gate is active the
 * fix is deliberately withheld and replaced by the question - the extension does
 * not get to be more permissive than the CLI.
 */
export function messageFor(f: Finding, showFix: boolean): string {
  const parts: string[] = [];
  const tierTag = f.tier === 'advisory' ? ' (advisory - a hint, not a finding)' : '';
  parts.push(`${f.severity_label.toUpperCase()}${tierTag}: ${f.title}`);
  parts.push('');
  parts.push(f.explanation);
  if (f.attack) {
    parts.push('');
    parts.push(`What an attacker does: ${f.attack}`);
  }
  if (f.question && !showFix) {
    parts.push('');
    parts.push(`Before the fix: ${f.question}`);
    parts.push(`Run "CodeSentinel: Answer the Comprehension Question" for ${f.rule_id}.`);
  } else if (f.fix) {
    parts.push('');
    parts.push('Fix:');
    parts.push(f.fix);
  }
  return parts.join('\n');
}

export function toDiagnostics(
  findings: Finding[],
  document?: vscode.TextDocument
): vscode.Diagnostic[] {
  const { showAdvisories, showFix, minSeverity } = getSettings();
  return findings
    .filter((f) => showAdvisories || f.tier !== 'advisory')
    // minSeverity applies to findings only. An advisory is a different kind of
    // claim, not a quieter one, so showAdvisories is what controls those.
    .filter((f) => f.tier === 'advisory' || f.severity >= minSeverity)
    .map((f) => {
      const d = new vscode.Diagnostic(rangeFor(f, document), messageFor(f, showFix), severityFor(f));
      d.source = 'CodeSentinel';
      d.code = {
        value: `${f.rule_id} ${f.cwe}`,
        target: vscode.Uri.parse(
          `https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`
        ),
      };
      return d;
    });
}

export function applyReport(
  collection: vscode.DiagnosticCollection,
  report: ScanReport
): number {
  let count = 0;
  for (const file of report.files) {
    const uri = vscode.Uri.file(file.path);
    const document = vscode.workspace.textDocuments.find((d) => d.uri.fsPath === uri.fsPath);
    const diagnostics = toDiagnostics(file.findings, document);
    collection.set(uri, diagnostics);
    count += diagnostics.length;
  }
  return count;
}
