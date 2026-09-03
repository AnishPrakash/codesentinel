import * as vscode from 'vscode';

import { ScanReport } from '../scanner';

/**
 * The last report for a document, keyed by path and validated by version.
 *
 * Switching tabs has to show the findings for the file you switched to, and
 * there are only two ways to do that: keep the last result, or spawn Python
 * again. A scanner that starts a process on every tab change is a scanner
 * people turn off, so we keep the result.
 *
 * `TextDocument.version` increments on every edit, which makes the staleness
 * check exact rather than a guess: if it has not changed, the bytes have not
 * changed, and the previous answer is still the right one. If it has, the entry
 * is dropped and the caller rescans.
 */

interface Entry {
  version: number;
  report: ScanReport;
}

const cache = new Map<string, Entry>();

export function remember(doc: vscode.TextDocument, report: ScanReport): void {
  cache.set(doc.uri.fsPath, { version: doc.version, report });
}

export function recall(doc: vscode.TextDocument): ScanReport | undefined {
  const entry = cache.get(doc.uri.fsPath);
  return entry && entry.version === doc.version ? entry.report : undefined;
}

export function forget(doc: vscode.TextDocument): void {
  cache.delete(doc.uri.fsPath);
}

export function clearCache(): void {
  cache.clear();
}
