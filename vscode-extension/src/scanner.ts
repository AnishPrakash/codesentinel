import { spawn } from 'child_process';
import * as vscode from 'vscode';

import { getSettings } from './utils/config';
import { logger } from './utils/logger';

/**
 * The bridge. The extension owns no detection logic of its own: it spawns
 *
 *     python -m codesentinel scan <path> --format json --no-ledger
 *
 * and renders what comes back. That is deliberate - the CLI and the extension
 * must never be able to disagree about whether a file is safe, and the only way
 * to guarantee that is for exactly one of them to decide.
 */

export type Tier = 'deterministic' | 'advisory';

export interface Finding {
  rule_id: string;
  title: string;
  severity: number;
  severity_label: string;
  cwe: string;
  owasp: string;
  line: number;
  end_line: number;
  column: number;
  snippet: string;
  language: string;
  tier: Tier;
  explanation: string;
  attack: string;
  fix: string;
  question: string;
  confidence: number;
}

export interface FileResult {
  path: string;
  language: string;
  lines: number;
  elapsed_ms: number;
  findings: Finding[];
  needs_review: { score: number; note: string } | null;
}

export interface ScanReport {
  files: FileResult[];
  coverage: string;
  stats: { files: number; findings: number; elapsed_ms: number };
}

export class ScannerUnavailableError extends Error {}

function runCli(args: string[]): Promise<string> {
  const { pythonPath, timeoutMs } = getSettings();
  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

  return new Promise((resolve, reject) => {
    logger.info(`spawn: ${pythonPath} -m codesentinel ${args.join(' ')}`);
    const child = spawn(pythonPath, ['-m', 'codesentinel', ...args], {
      cwd,
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', NO_COLOR: '1' },
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      child.kill();
      reject(new Error(`CodeSentinel timed out after ${timeoutMs} ms`));
    }, timeoutMs);

    child.stdout.on('data', (d) => (stdout += d.toString()));
    child.stderr.on('data', (d) => (stderr += d.toString()));

    child.on('error', (err) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      reject(
        new ScannerUnavailableError(
          `Could not run "${pythonPath} -m codesentinel". ${err.message}`
        )
      );
    });

    child.on('close', (code) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      // A missing module also exits 1, so check this BEFORE trusting the code.
      if (/No module named/i.test(stderr)) {
        const missing = /No module named '([^']+)'/.exec(stderr)?.[1];
        reject(
          new ScannerUnavailableError(
            missing && missing !== 'codesentinel'
              ? `CodeSentinel is installed but its dependency "${missing}" is not. ` +
                  'Run `pip install -r requirements.txt` in the repo.'
              : 'CodeSentinel is not installed in the selected interpreter. ' +
                  'Run `pip install -e .` in the repo, then set codesentinel.pythonPath.'
          )
        );
        return;
      }

      // Exit code 1 means findings were reported at or above the threshold -
      // a successful scan, not a failure. But a Python traceback ALSO exits 1
      // with empty stdout, so the exit code alone cannot tell them apart.
      // Whether stdout carries a JSON body is what actually distinguishes them.
      if (code === 0 || (code === 1 && stdout.includes('{'))) {
        resolve(stdout);
        return;
      }
      if (code === 1) {
        reject(
          new Error(
            'CodeSentinel exited without producing a report. ' +
              (stderr.trim().split('\n').pop() || 'No error output.')
          )
        );
        return;
      }
      reject(new Error(stderr.trim() || `codesentinel exited with code ${code}`));
    });
  });
}

/** Strip anything the CLI printed before the JSON body (skip notices, warnings). */
function parseReport(raw: string): ScanReport {
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start === -1 || end === -1) {
    throw new Error('CodeSentinel returned no JSON. Run "CodeSentinel: Show Log".');
  }
  return JSON.parse(raw.slice(start, end + 1)) as ScanReport;
}

export async function scanPath(fsPath: string): Promise<ScanReport> {
  // --no-ledger: an editor scanning on every save would otherwise fill the
  // local history with noise the user never asked for.
  const raw = await runCli(['scan', fsPath, '--format', 'json', '--no-ledger']);
  return parseReport(raw);
}

export async function scanWorkspaceFolder(folder: string): Promise<ScanReport> {
  return scanPath(folder);
}

export async function checkAvailable(): Promise<string | null> {
  try {
    const out = await runCli(['version']);
    return out.trim();
  } catch (err) {
    logger.error('availability check failed', err);
    return null;
  }
}
