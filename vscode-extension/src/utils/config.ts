import * as vscode from 'vscode';

export interface Settings {
  pythonPath: string;
  scanOnSave: boolean;
  showAdvisories: boolean;
  showFix: boolean;
  gutterIcons: boolean;
  timeoutMs: number;
}

export const SUPPORTED_LANGUAGES = [
  'python',
  'javascript',
  'javascriptreact',
  'typescript',
  'typescriptreact',
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
  };
}

export function isSupported(document: vscode.TextDocument): boolean {
  return SUPPORTED_LANGUAGES.includes(document.languageId) && document.uri.scheme === 'file';
}
