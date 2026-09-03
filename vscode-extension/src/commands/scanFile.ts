import * as vscode from 'vscode';

import { applyDecorations } from '../decorations';
import { applyReport } from '../diagnostics';
import { ScanReport, ScannerUnavailableError, scanPath } from '../scanner';
import { SidebarProvider } from '../sidebar/SidebarProvider';
import { isSupported } from '../utils/config';
import { logger } from '../utils/logger';

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
    collection.delete(doc.uri);
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
