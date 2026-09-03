import * as vscode from 'vscode';

export interface Settings {
  pythonPath: string;
  scanOnSave: boolean;
  showAdvisories: boolean;
  showFix: boolean;
  gutterIcons: boolean;
  timeoutMs: number;
  minSeverity: number;
}

/** Severity names as the CLI numbers them (Severity is an IntEnum in Python). */
export const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const SUPPORTED_LANGUAGES = [
  'python',
  'javascript',
  'javascriptreact',
  'typescript',
  'typescriptreact',
  'java',
];

export function getSettings(): Settings {
  const c = vscode.workspace.getConfiguration('codesentinel');
  return {
    pythonPath: c.get<string>('pythonPath', 'python'),
    scanOnSave: c.get<boolean>('scanOnSave', true),
    showAdvisories: c.get<boolean>('showAdvisories', true),
    showFix: c.get<boolean>('showFix', false),
    gutterIcons: c.get<boolean>('gutterIcons', true),
    timeoutMs: c.get<number>('timeoutMs', 30000),
    minSeverity: SEVERITY_RANK[c.get<string>('minSeverity', 'low')] ?? 1,
  };
}

export function isSupported(document: vscode.TextDocument): boolean {
  return SUPPORTED_LANGUAGES.includes(document.languageId) && document.uri.scheme === 'file';
}
