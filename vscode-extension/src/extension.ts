import * as vscode from 'vscode';

import { learn } from './commands/learn';
import { scanFile } from './commands/scanFile';
import { scanWorkspace } from './commands/scanWorkspace';
import { showProgress } from './commands/showProgress';
import { clearDecorations, disposeDecorations } from './decorations';
import { COLLECTION_NAME } from './diagnostics';
import { checkAvailable } from './scanner';
import { SidebarProvider } from './sidebar/SidebarProvider';
import { getSettings, isSupported } from './utils/config';
import { logger } from './utils/logger';

let collection: vscode.DiagnosticCollection;
let sidebar: SidebarProvider;
let status: vscode.StatusBarItem;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  logger.info('CodeSentinel activating');

  collection = vscode.languages.createDiagnosticCollection(COLLECTION_NAME);
  sidebar = new SidebarProvider();
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = 'codesentinel.scanFile';
  status.text = '$(shield) CodeSentinel';

  context.subscriptions.push(
    collection,
    status,
    vscode.window.registerTreeDataProvider('codesentinel.findings', sidebar),

    vscode.commands.registerCommand('codesentinel.scanFile', () =>
      scanFile(collection, sidebar, status)
    ),
    vscode.commands.registerCommand('codesentinel.scanWorkspace', () =>
      scanWorkspace(collection, sidebar)
    ),
    vscode.commands.registerCommand('codesentinel.clearDiagnostics', () => {
      collection.clear();
      sidebar.clear();
      vscode.window.visibleTextEditors.forEach(clearDecorations);
      status.text = '$(shield) CodeSentinel';
    }),
    vscode.commands.registerCommand('codesentinel.learn', () => learn()),
    vscode.commands.registerCommand('codesentinel.showProgress', () => showProgress()),
    vscode.commands.registerCommand('codesentinel.showOutput', () => logger.show()),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (getSettings().scanOnSave && isSupported(doc)) {
        void scanFile(collection, sidebar, status, doc, true);
      }
    }),

    vscode.workspace.onDidCloseTextDocument((doc) => collection.delete(doc.uri))
  );

  // Availability is checked once, in the background, and reported as a message
  // rather than a modal - the extension must never block the editor starting.
  void checkAvailable().then((version) => {
    if (version) {
      logger.info(`CLI available: ${version.split('\n')[0]}`);
      status.show();
    } else {
      status.text = '$(shield) not installed';
      status.tooltip =
        'CodeSentinel CLI not found. Set codesentinel.pythonPath to the interpreter ' +
        'where it is installed.';
      status.show();
      logger.info('CLI not found on the configured interpreter');
    }
  });

  const active = vscode.window.activeTextEditor?.document;
  if (active && isSupported(active)) {
    void scanFile(collection, sidebar, status, active, true);
  }
}

export function deactivate(): void {
  disposeDecorations();
  logger.dispose();
}
