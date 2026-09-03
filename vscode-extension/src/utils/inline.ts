/**
 * The text CodeSentinel renders at the end of a line, and nothing else.
 *
 * This file imports no vscode API on purpose: the rule about what a one-line
 * summary may say is the part worth testing, and a pure module can be run by
 * `node scripts/verify-inline.js` without an editor.
 *
 * Why this exists at all: a vscode.Diagnostic is only a squiggle, a Problems
 * row and a hover. Users who wanted to read the message in the editor were
 * installing Error Lens - a third-party extension - which then also rendered
 * every Pylance type hint at the same volume, so turning it off to silence the
 * type checker silenced us too. A tool whose whole premise is "explain the
 * finding where the developer is looking" should not outsource that to an
 * extension it does not control.
 *
 * The inline label is deliberately NOT the diagnostic message. The diagnostic
 * message is several paragraphs - title, mechanism, what an attacker does, and
 * either the fix or the comprehension question - which is right for a hover and
 * absurd at the end of a line of code. Inline gets the claim; the hover keeps
 * the reasoning.
 */

export type InlineKind = 'critical' | 'warning' | 'advisory';

export interface InlineInput {
  line: number;
  severity: number;
  severity_label: string;
  rule_id: string;
  title: string;
  tier: 'deterministic' | 'advisory';
}

export interface InlineLabel {
  line: number;
  text: string;
  kind: InlineKind;
}

const ELLIPSIS = '…';

export function kindFor(f: InlineInput): InlineKind {
  if (f.tier === 'advisory') {
    return 'advisory';
  }
  return f.severity >= 4 ? 'critical' : 'warning';
}

export function truncate(text: string, max: number): string {
  if (max <= 1 || text.length <= max) {
    return text;
  }
  return text.slice(0, max - 1).trimEnd() + ELLIPSIS;
}

/**
 * One label for one finding.
 *
 * The severity word and the rule id are never truncated - only the title is.
 * Cutting "CS001" off the end to fit a column budget would leave a message the
 * user cannot look up, which is worse than a shortened title.
 *
 * An advisory is labelled ADVISORY rather than by its severity, because its
 * severity number is not a claim about how bad the code is; it is how confident
 * the heuristic is that something is absent.
 */
export function labelFor(f: InlineInput, maxLength: number): string {
  const tag = f.tier === 'advisory' ? 'ADVISORY' : f.severity_label.toUpperCase();
  const prefix = `${tag} ${f.rule_id}: `;
  const budget = Math.max(8, maxLength - prefix.length);
  return prefix + truncate(f.title, budget);
}

/**
 * Collapse the findings on a line into a single label.
 *
 * Several findings can land on one line, and stacking their text would push the
 * code off screen. The worst one is shown and the rest are counted, so nothing
 * silently disappears - the count is the promise that the Problems panel has
 * more.
 */
export function inlineLabels(findings: InlineInput[], maxLength = 100): InlineLabel[] {
  const byLine = new Map<number, InlineInput[]>();
  for (const f of findings) {
    const bucket = byLine.get(f.line);
    if (bucket) {
      bucket.push(f);
    } else {
      byLine.set(f.line, [f]);
    }
  }

  const out: InlineLabel[] = [];
  for (const [line, bucket] of byLine) {
    // Deterministic before advisory, then worst severity, then rule id so the
    // choice is stable between scans of an unchanged file.
    const sorted = [...bucket].sort((a, b) => {
      const tier = Number(a.tier === 'advisory') - Number(b.tier === 'advisory');
      if (tier !== 0) {
        return tier;
      }
      if (a.severity !== b.severity) {
        return b.severity - a.severity;
      }
      return a.rule_id.localeCompare(b.rule_id);
    });
    const worst = sorted[0];
    const extra = sorted.length - 1;
    const suffix = extra > 0 ? `  (+${extra} more)` : '';
    out.push({
      line,
      text: labelFor(worst, maxLength) + suffix,
      kind: kindFor(worst),
    });
  }
  return out.sort((a, b) => a.line - b.line);
}
