import { spawn } from 'child_process';
import * as vscode from 'vscode';

import { getSettings } from '../utils/config';
import { logger } from '../utils/logger';

/** `cs progress`, rendered into an editor tab. The ledger stays local. */
export async function showProgress(): Promise<void> {
  const { pythonPath, timeoutMs } = getSettings();

  const output = await new Promise<string>((resolve, reject) => {
    const child = spawn(pythonPath, ['-m', 'codesentinel', 'progress'], {
      cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', NO_COLOR: '1' },
    });
    let out = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('CodeSentinel timed out'));
    }, timeoutMs);
    child.stdout.on('data', (d) => (out += d.toString()));
    child.stderr.on('data', (d) => (out += d.toString()));
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', () => {
      clearTimeout(timer);
      resolve(out);
    });
  }).catch((err) => {
    logger.error('progress failed', err);
    vscode.window.showErrorMessage(`CodeSentinel: ${(err as Error).message}`);
    return '';
  });

  if (!output.trim()) {
    return;
  }

  const doc = await vscode.workspace.openTextDocument({
    content: output,
    language: 'plaintext',
  });
  await vscode.window.showTextDocument(doc, { preview: true });
}
