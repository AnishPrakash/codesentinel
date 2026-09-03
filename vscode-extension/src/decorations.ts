import * as vscode from 'vscode';

import { Finding } from './scanner';
import { getSettings } from './utils/config';
import { InlineKind, inlineLabels } from './utils/inline';
import { logger } from './utils/logger';

/**
 * Line highlights and end-of-line messages, kept visually distinct by tier.
 * Advisories get a muted treatment on purpose: the editor should make the
 * difference between "this is true" and "this might be worth checking" legible
 * without reading anything.
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

/**
 * One decoration type for every inline message; the text and colour vary per
 * range through DecorationOptions.renderOptions. A type per line would leak a
 * disposable for every finding in every file.
 */
const inline = vscode.window.createTextEditorDecorationType({
  isWholeLine: false,
  rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
});

const INLINE_COLOR: Record<InlineKind, string> = {
  critical: 'editorError.foreground',
  warning: 'editorWarning.foreground',
  advisory: 'editorHint.foreground',
};

export const allDecorationTypes = [critical, warning, advisory, inline];

/**
 * The findings last drawn for a file, so a decoration can be redrawn without a
 * rescan. Decorations live on an editor, not on a document: switching tabs and
 * coming back gives you a new editor with nothing on it. Rescanning to repaint
 * would spawn a Python process every time the user changes tab.
 */
const lastFindings = new Map<string, Finding[]>();

export function clearDecorations(editor: vscode.TextEditor): void {
  for (const type of allDecorationTypes) {
    editor.setDecorations(type, []);
  }
}

export function forgetDecorations(): void {
  lastFindings.clear();
}

/** Repaint every visible editor from what was last scanned. */
export function refreshDecorations(): void {
  for (const editor of vscode.window.visibleTextEditors) {
    const findings = lastFindings.get(editor.document.uri.fsPath);
    if (findings) {
      applyDecorations(editor, findings);
    }
  }
}

let lastInlineReason = '';

/**
 * Should CodeSentinel draw its own end-of-line text?
 *
 * On "auto" it stands down when Error Lens is installed and enabled, because
 * two extensions rendering the same diagnostic at the end of the same line is
 * worse than either alone. Disabling Error Lens - or excluding it by source -
 * brings ours back with no further configuration, which is the case that sent
 * users looking for this setting in the first place.
 */
function inlineEnabled(): boolean {
  const mode = getSettings().inlineMessage;
  let on: boolean;
  let reason: string;

  if (mode === 'on') {
    on = true;
    reason = 'inlineMessage=on';
  } else if (mode === 'off') {
    on = false;
    reason = 'inlineMessage=off';
  } else {
    const lens = vscode.extensions.getExtension('usernamehw.errorlens');
    if (!lens) {
      on = true;
      reason = 'auto: Error Lens not installed or disabled';
    } else {
      const lensOn = vscode.workspace.getConfiguration('errorLens').get<boolean>('enabled', true);
      on = !lensOn;
      reason = lensOn
        ? 'auto: Error Lens is enabled, standing down (set codesentinel.inlineMessage to "on" to override)'
        : 'auto: Error Lens installed but errorLens.enabled is false';
    }
  }

  // "auto" makes a decision the user cannot see. Say what it decided, once per
  // change - a silent mode that picks wrong is indistinguishable from a bug.
  if (reason !== lastInlineReason) {
    lastInlineReason = reason;
    logger.info(`inline messages ${on ? 'on' : 'off'} - ${reason}`);
  }
  return on;
}

function inlineOptions(
  editor: vscode.TextEditor,
  findings: Finding[]
): vscode.DecorationOptions[] {
  const { inlineMessageMaxLength } = getSettings();
  const labels = inlineLabels(
    findings.map((f) => ({
      line: f.line,
      severity: f.severity,
      severity_label: f.severity_label,
      rule_id: f.rule_id,
      title: f.title,
      tier: f.tier,
    })),
    inlineMessageMaxLength
  );

  return labels.map((label) => {
    const line = Math.min(Math.max(0, label.line - 1), editor.document.lineCount - 1);
    // Anchor at the end of the line so the label never sits on top of code.
    const end = editor.document.lineAt(line).range.end;
    return {
      range: new vscode.Range(end, end),
      renderOptions: {
        after: {
          contentText: `  ${label.text}`,
          color: new vscode.ThemeColor(INLINE_COLOR[label.kind]),
          fontStyle: label.kind === 'advisory' ? 'italic' : 'normal',
          margin: '0 0 0 1em',
        },
      },
    };
  });
}

export function applyDecorations(editor: vscode.TextEditor, findings: Finding[]): void {
  clearDecorations(editor);
  lastFindings.set(editor.document.uri.fsPath, findings);
  const { gutterIcons, showAdvisories } = getSettings();

  // The same filter the diagnostics use. A finding the user asked not to see
  // must not come back as a highlight or a label.
  const visible = findings.filter((f) => showAdvisories || f.tier !== 'advisory');

  if (gutterIcons) {
    const buckets = new Map<vscode.TextEditorDecorationType, vscode.Range[]>([
      [critical, []],
      [warning, []],
      [advisory, []],
    ]);

    for (const f of visible) {
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

  if (inlineEnabled()) {
    editor.setDecorations(inline, inlineOptions(editor, visible));
  }
}

export function disposeDecorations(): void {
  for (const type of allDecorationTypes) {
    type.dispose();
  }
}
