import * as vscode from 'vscode';

import { Finding } from './scanner';
import { getSettings } from './utils/config';

/**
 * Line highlights, kept visually distinct by tier. Advisories get a muted
 * treatment on purpose: the editor should make the difference between "this is
 * true" and "this might be worth checking" legible without reading anything.
 */

const critical = vscode.window.createTextEditorDecorationType({
  isWholeLine: true,
  backgroundColor: new vscode.ThemeColor('inputValidation.errorBackground'),
  overviewRulerColor: new vscode.ThemeColor('editorError.foreground'),
  overviewRulerLane: vscode.OverviewRulerLane.Right,
});

const warning = vscode.window.createTextEditorDecorationType({
  isWholeLine: true,
  backgroundColor: new vscode.ThemeColor('inputValidation.warningBackground'),
  overviewRulerColor: new vscode.ThemeColor('editorWarning.foreground'),
  overviewRulerLane: vscode.OverviewRulerLane.Right,
});

const advisory = vscode.window.createTextEditorDecorationType({
  isWholeLine: false,
  after: {
    contentText: '  advisory',
    color: new vscode.ThemeColor('editorHint.foreground'),
    fontStyle: 'italic',
  },
});

export const allDecorationTypes = [critical, warning, advisory];

export function clearDecorations(editor: vscode.TextEditor): void {
  for (const type of allDecorationTypes) {
    editor.setDecorations(type, []);
  }
}

export function applyDecorations(editor: vscode.TextEditor, findings: Finding[]): void {
  clearDecorations(editor);
  if (!getSettings().gutterIcons) {
    return;
  }

  const buckets = new Map<vscode.TextEditorDecorationType, vscode.Range[]>([
    [critical, []],
    [warning, []],
    [advisory, []],
  ]);

  for (const f of findings) {
    const line = Math.min(Math.max(0, f.line - 1), editor.document.lineCount - 1);
    const range = editor.document.lineAt(line).range;
    if (f.tier === 'advisory') {
      buckets.get(advisory)!.push(range);
    } else if (f.severity >= 4) {
      buckets.get(critical)!.push(range);
    } else {
      buckets.get(warning)!.push(range);
    }
  }

  for (const [type, ranges] of buckets) {
    editor.setDecorations(type, ranges);
  }
}

export function disposeDecorations(): void {
  for (const type of allDecorationTypes) {
    type.dispose();
  }
}
