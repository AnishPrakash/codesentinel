import * as path from 'path';
import * as vscode from 'vscode';

import { Finding, ScanReport } from '../scanner';

/**
 * The findings tree. Two top-level groups, Findings and Advisories, because
 * collapsing them would hide the one distinction the whole product rests on.
 */

type Node = GroupNode | FileNode | FindingNode;

class GroupNode {
  readonly kind = 'group';
  constructor(readonly label: string, readonly files: FileNode[]) {}
}

class FileNode {
  readonly kind = 'file';
  constructor(readonly fsPath: string, readonly findings: Finding[]) {}
}

class FindingNode {
  readonly kind = 'finding';
  constructor(readonly fsPath: string, readonly finding: Finding) {}
}

export class SidebarProvider implements vscode.TreeDataProvider<Node> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<Node | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private report: ScanReport | undefined;

  setReport(report: ScanReport | undefined): void {
    this.report = report;
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.setReport(undefined);
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === 'group') {
      const total = node.files.reduce((n, f) => n + f.findings.length, 0);
      const item = new vscode.TreeItem(
        `${node.label} (${total})`,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.iconPath = new vscode.ThemeIcon(node.label === 'Findings' ? 'shield' : 'info');
      return item;
    }

    if (node.kind === 'file') {
      const item = new vscode.TreeItem(
        path.basename(node.fsPath),
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.description = vscode.workspace.asRelativePath(node.fsPath);
      item.resourceUri = vscode.Uri.file(node.fsPath);
      return item;
    }

    const f = node.finding;
    const item = new vscode.TreeItem(f.title, vscode.TreeItemCollapsibleState.None);
    item.description = `line ${f.line} · ${f.rule_id} · ${f.cwe}`;
    item.tooltip = new vscode.MarkdownString(
      `**${f.severity_label}${f.tier === 'advisory' ? ' (advisory)' : ''}** — ${f.title}\n\n` +
        `${f.explanation}\n\n` +
        (f.question ? `_Before the fix:_ ${f.question}` : '')
    );
    item.iconPath = new vscode.ThemeIcon(
      f.tier === 'advisory' ? 'lightbulb' : f.severity >= 4 ? 'error' : 'warning'
    );
    item.command = {
      command: 'vscode.open',
      title: 'Open',
      arguments: [
        vscode.Uri.file(node.fsPath),
        {
          selection: new vscode.Range(
            Math.max(0, f.line - 1),
            f.column,
            Math.max(0, f.line - 1),
            f.column
          ),
        } satisfies vscode.TextDocumentShowOptions,
      ],
    };
    return item;
  }

  getChildren(node?: Node): Node[] {
    if (!this.report) {
      return [];
    }

    if (!node) {
      const findings = this.filesFor((f) => f.tier === 'deterministic');
      const advisories = this.filesFor((f) => f.tier === 'advisory');
      const groups: GroupNode[] = [];
      if (findings.length) {
        groups.push(new GroupNode('Findings', findings));
      }
      if (advisories.length) {
        groups.push(new GroupNode('Advisories', advisories));
      }
      return groups;
    }

    if (node.kind === 'group') {
      return node.files;
    }
    if (node.kind === 'file') {
      return node.findings.map((f) => new FindingNode(node.fsPath, f));
    }
    return [];
  }

  private filesFor(predicate: (f: Finding) => boolean): FileNode[] {
    if (!this.report) {
      return [];
    }
    return this.report.files
      .map((file) => new FileNode(file.path, file.findings.filter(predicate)))
      .filter((file) => file.findings.length > 0);
  }
}
