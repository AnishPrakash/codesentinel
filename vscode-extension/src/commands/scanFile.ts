import * as vscode from 'vscode';

import { applyDecorations } from '../decorations';
import { applyReport } from '../diagnostics';
import { ScanReport, ScannerUnavailableError, scanPath } from '../scanner';
import { SidebarProvider } from '../sidebar/SidebarProvider';
import { isSupported } from '../utils/config';
import { logger } from '../utils/logger';
import { recall, remember } from '../utils/scanCache';

export async function scanFile(
  collection: vscode.DiagnosticCollection,
  sidebar: SidebarProvider,
  status: vscode.StatusBarItem,
  document?: vscode.TextDocument,
  silent = false
): Promise<ScanReport | undefined> {
  const doc = document ?? vscode.window.activeTextEditor?.document;
  if (!doc) {
    if (!silent) {
      vscode.window.showInformationMessage('CodeSentinel: open a file to scan.');
    }
    return undefined;
  }
  if (!isSupported(doc)) {
    if (!silent) {
      vscode.window.showInformationMessage(
        'CodeSentinel supports Python and JavaScript/TypeScript files.'
      );
    }
    return undefined;
  }

  status.text = '$(sync~spin) CodeSentinel';
  status.show();

  try {
    const report = await scanPath(doc.uri.fsPath);
    remember(doc, report);
    collection.delete(doc.uri);
    const count = present(collection, sidebar, status, doc, report);
    logger.info(`${doc.uri.fsPath}: ${count} diagnostic(s)`);
    return report;
  } catch (err) {
    status.text = '$(shield) error';
    if (err instanceof ScannerUnavailableError) {
      logger.error('scanner unavailable', err);
      if (!silent) {
        const choice = await vscode.window.showErrorMessage(
          err.message,
          'Open Settings',
          'Show Log'
        );
        if (choice === 'Open Settings') {
          void vscode.commands.executeCommand(
            'workbench.action.openSettings',
            'codesentinel.pythonPath'
          );
        } else if (choice === 'Show Log') {
          logger.show();
        }
      }
    } else {
      logger.error('scan failed', err);
      if (!silent) {
        vscode.window.showErrorMessage(`CodeSentinel: ${(err as Error).message}`);
      }
    }
    return undefined;
  }
}


/**
 * Render a report into the editor: diagnostics, sidebar, decorations, status.
 *
 * Separate from scanning because showing a file is not the same as scanning it.
 * A tab switch back to a file that has not changed needs everything below and
 * none of the process spawn above.
 */
function present(
  collection: vscode.DiagnosticCollection,
  sidebar: SidebarProvider,
  status: vscode.StatusBarItem,
  doc: vscode.TextDocument,
  report: ScanReport
): number {
  const count = applyReport(collection, report);
  sidebar.setReport(report);

  const editor = vscode.window.visibleTextEditors.find(
    (e) => e.document.uri.fsPath === doc.uri.fsPath
  );
  if (editor) {
    applyDecorations(editor, report.files[0]?.findings ?? []);
  }

  const deterministic =
    report.files[0]?.findings.filter((f) => f.tier === 'deterministic').length ?? 0;
  status.text = deterministic > 0 ? `$(shield) ${deterministic}` : '$(shield) clean';
  status.tooltip = report.coverage;
  status.show();
  return count;
}

/**
 * Show findings for the file the user just switched to.
 *
 * The extension used to scan exactly two things: the document that happened to
 * be active when it activated, and anything you saved. Every other file in the
 * project looked clean - not "not scanned yet", clean - which is the worst
 * failure mode a security tool has. Silence has to mean "we looked", so
 * becoming the active editor is now a reason to look.
 */
export async function showFile(
  collection: vscode.DiagnosticCollection,
  sidebar: SidebarProvider,
  status: vscode.StatusBarItem,
  doc: vscode.TextDocument
): Promise<void> {
  if (!isSupported(doc)) {
    return;
  }
  const cached = recall(doc);
  if (cached) {
    present(collection, sidebar, status, doc, cached);
    return;
  }
  await scanFile(collection, sidebar, status, doc, true);
}
