import { spawn } from 'child_process';
import * as vscode from 'vscode';

import { getSettings } from '../utils/config';
import { logger } from '../utils/logger';

/**
 * The comprehension gate, in the editor.
 *
 * The grading is not reimplemented here. The answer is piped to
 * `python -m codesentinel learn <rule>` and the CLI's own deterministic rubric
 * decides - so the extension cannot accidentally be a softer marker than the
 * command line, and the pass is written to the same local ledger.
 */

const RULES_WITH_QUESTIONS = [
  'CS001',
  'CS002',
  'CS003',
  'CS004',
  'CS005',
  'CS006',
  'CS007',
  'CS008',
  'CS009',
];

function runLearn(ruleId: string, answer: string): Promise<{ passed: boolean; output: string }> {
  const { pythonPath, timeoutMs } = getSettings();
  return new Promise((resolve, reject) => {
    const child = spawn(pythonPath, ['-m', 'codesentinel', 'learn', ruleId], {
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
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ passed: code === 0, output: out });
    });

    // One answer, then close stdin. Three wrong answers in the CLI print the
    // explanation; here we ask once per invocation and let the user retry.
    child.stdin.write(`${answer.replace(/\r?\n/g, ' ')}\n`);
    child.stdin.end();
  });
}

/** Pull the grader's feedback line out of the CLI's rendered output. */
function feedbackFrom(output: string): string {
  const flat = output.replace(/\s+/g, ' ');
  const match = flat.match(
    /(That is right[^.]*\.|That is too short[^.]*\.[^.]*\.|Close, but something is missing\.[^]*?)(?:\s*╭|$)/
  );
  return match ? match[1].trim() : flat.slice(0, 400).trim();
}

export async function learn(preselected?: string): Promise<void> {
  const ruleId =
    preselected ??
    (await vscode.window.showQuickPick(RULES_WITH_QUESTIONS, {
      placeHolder: 'Which class do you want to explain?',
    }));
  if (!ruleId) {
    return;
  }

  const answer = await vscode.window.showInputBox({
    prompt: `${ruleId} - explain the mechanism in your own words`,
    placeHolder: 'What actually happens, and why the fix removes it',
    ignoreFocusOut: true,
  });
  if (!answer) {
    return;
  }

  try {
    const { passed, output } = await runLearn(ruleId, answer);
    const feedback = feedbackFrom(output);
    logger.info(`learn ${ruleId}: ${passed ? 'passed' : 'not yet'}`);

    if (passed) {
      vscode.window.showInformationMessage(`CodeSentinel: ${feedback}`);
      const doc = await vscode.workspace.openTextDocument({
        content: output,
        language: 'markdown',
      });
      await vscode.window.showTextDocument(doc, { preview: true });
    } else {
      const choice = await vscode.window.showWarningMessage(
        `CodeSentinel: ${feedback}`,
        'Try again'
      );
      if (choice === 'Try again') {
        await learn(ruleId);
      }
    }
  } catch (err) {
    logger.error('learn failed', err);
    vscode.window.showErrorMessage(`CodeSentinel: ${(err as Error).message}`);
  }
}
