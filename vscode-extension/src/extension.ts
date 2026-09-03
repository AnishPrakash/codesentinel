import * as vscode from 'vscode';

import { learn } from './commands/learn';
import { scanFile, showFile } from './commands/scanFile';
import { scanWorkspace } from './commands/scanWorkspace';
import { showProgress } from './commands/showProgress';
import {
  clearDecorations,
  disposeDecorations,
  forgetDecorations,
  refreshDecorations,
} from './decorations';
import { COLLECTION_NAME } from './diagnostics';
import { checkAvailable } from './scanner';
import { SidebarProvider } from './sidebar/SidebarProvider';
import { getSettings, isSupported } from './utils/config';
import { logger } from './utils/logger';
import { clearCache, forget } from './utils/scanCache';

let collection: vscode.DiagnosticCollection;
let sidebar: SidebarProvider;
let status: vscode.StatusBarItem;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  // Which build is actually running, and from where.
  //
  // An installed .vsix takes precedence over the Extension Development Host, so
  // a stale install silently shadows the working tree and every rebundle looks
  // like it did nothing. The version alone does not disambiguate them - the
  // packaged build and the source it was packaged from share it - so the mode
  // and the path are the part that answers the question.
  const mode =
    context.extensionMode === vscode.ExtensionMode.Development ? 'development host' : 'installed';
  logger.info(
    `CodeSentinel ${context.extension.packageJSON.version} activating ` +
      `(${mode}, ${context.extensionPath})`
  );

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
      forgetDecorations();
      clearCache();
      status.text = '$(shield) CodeSentinel';
    }),
    vscode.commands.registerCommand('codesentinel.toggleInlineMessages', async () => {
      const c = vscode.workspace.getConfiguration('codesentinel');
      const next = c.get<string>('inlineMessage', 'auto') === 'off' ? 'on' : 'off';
      await c.update('inlineMessage', next, vscode.ConfigurationTarget.Global);
      // The configuration listener repaints; this only reports.
      vscode.window.setStatusBarMessage(
        `CodeSentinel inline messages: ${next}`,
        3000
      );
    }),
    vscode.commands.registerCommand('codesentinel.learn', () => learn()),
    vscode.commands.registerCommand('codesentinel.showProgress', () => showProgress()),
    vscode.commands.registerCommand('codesentinel.showOutput', () => logger.show()),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (getSettings().scanOnSave && isSupported(doc)) {
        void scanFile(collection, sidebar, status, doc, true);
      }
    }),

    // Becoming the active editor is a reason to scan. Without this the only
    // scanned file is whichever one happened to be open at startup, and every
    // other file in the project reads as clean rather than as unexamined.
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        void showFile(collection, sidebar, status, editor.document);
      }
    }),

    vscode.workspace.onDidCloseTextDocument((doc) => {
      collection.delete(doc.uri);
      forget(doc);
    }),

    // Decorations live on an editor, not a document, so switching tabs loses
    // them. Repaint from the last scan rather than spawning Python again.
    vscode.window.onDidChangeVisibleTextEditors(() => refreshDecorations()),

    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration('codesentinel') ||
        e.affectsConfiguration('errorLens.enabled')
      ) {
        refreshDecorations();
      }
    })
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
    void showFile(collection, sidebar, status, active);
  }
}

export function deactivate(): void {
  disposeDecorations();
  logger.dispose();
}
