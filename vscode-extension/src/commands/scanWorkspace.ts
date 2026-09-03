import * as vscode from 'vscode';

import { applyReport } from '../diagnostics';
import { ScannerUnavailableError, scanWorkspaceFolder } from '../scanner';
import { SidebarProvider } from '../sidebar/SidebarProvider';
import { logger } from '../utils/logger';

export async function scanWorkspace(
  collection: vscode.DiagnosticCollection,
  sidebar: SidebarProvider
): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showInformationMessage('CodeSentinel: open a folder first.');
    return;
  }

  const folder =
    folders.length === 1
      ? folders[0]
      : await vscode.window.showWorkspaceFolderPick({ placeHolder: 'Folder to scan' });
  if (!folder) {
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `CodeSentinel: scanning ${folder.name}`,
      cancellable: false,
    },
    async () => {
      try {
        const report = await scanWorkspaceFolder(folder.uri.fsPath);
        collection.clear();
        const count = applyReport(collection, report);
        sidebar.setReport(report);

        const deterministic = report.files.reduce(
          (n, f) => n + f.findings.filter((x) => x.tier === 'deterministic').length,
          0
        );
        const advisories = report.stats.findings - deterministic;
        vscode.window.showInformationMessage(
          `CodeSentinel: ${deterministic} finding(s)` +
            (advisories ? `, ${advisories} advisory` : '') +
            ` across ${report.stats.files} file(s) in ${Math.round(report.stats.elapsed_ms)} ms.`
        );
        logger.info(`workspace scan: ${count} diagnostic(s)`);
      } catch (err) {
        if (err instanceof ScannerUnavailableError) {
          vscode.window.showErrorMessage(err.message);
        } else {
          vscode.window.showErrorMessage(`CodeSentinel: ${(err as Error).message}`);
        }
        logger.error('workspace scan failed', err);
      }
    }
  );
}
