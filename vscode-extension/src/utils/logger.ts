import * as vscode from 'vscode';

/**
 * One output channel for the whole extension. Every failure path writes here
 * rather than throwing a modal at the user - a security scanner that interrupts
 * you with dialogs gets disabled within a day.
 */
class Logger {
  private channel: vscode.OutputChannel | undefined;

  private get out(): vscode.OutputChannel {
    if (!this.channel) {
      this.channel = vscode.window.createOutputChannel('CodeSentinel');
    }
    return this.channel;
  }

  info(message: string): void {
    this.out.appendLine(`[${new Date().toISOString()}] ${message}`);
  }

  error(message: string, err?: unknown): void {
    const detail = err instanceof Error ? `${err.message}\n${err.stack ?? ''}` : String(err ?? '');
    this.out.appendLine(`[${new Date().toISOString()}] ERROR ${message} ${detail}`.trim());
  }

  show(): void {
    this.out.show(true);
  }

  dispose(): void {
    this.channel?.dispose();
    this.channel = undefined;
  }
}

export const logger = new Logger();
