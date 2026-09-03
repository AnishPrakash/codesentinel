#!/usr/bin/env node
/**
 * Tests for the inline-label rules.
 *
 * src/utils/inline.ts imports nothing from vscode, so it can be bundled to CJS
 * with the esbuild that is already a devDependency and asserted against here.
 * That is the whole reason the module is separate from decorations.ts: the
 * decision about what a one-line summary is allowed to say is a rule, and rules
 * get tests.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const esbuild = require('esbuild');

const src = path.join(__dirname, '..', 'src', 'utils', 'inline.ts');
const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-inline-')), 'inline.js');

esbuild.buildSync({
  entryPoints: [src],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  outfile: out,
});

const { inlineLabels, labelFor, truncate, kindFor } = require(out);

function finding(over) {
  return {
    line: 1,
    severity: 4,
    severity_label: 'critical',
    rule_id: 'CS001',
    title: 'Hardcoded credential in source',
    tier: 'deterministic',
    ...over,
  };
}

const tests = {
  'a critical finding reads as one line'() {
    const [label] = inlineLabels([finding()]);
    assert.strictEqual(label.text, 'CRITICAL CS001: Hardcoded credential in source');
    assert.strictEqual(label.kind, 'critical');
    assert.strictEqual(label.line, 1);
  },

  'the rule id survives a tight budget'() {
    // The point of the label is that the user can look the finding up. A
    // budget small enough to eat "CS001" must eat the title instead.
    const text = labelFor(finding({ title: 'A'.repeat(200) }), 30);
    assert.ok(text.startsWith('CRITICAL CS001: '), text);
    assert.ok(text.endsWith('…'), text);
  },

  'an advisory is labelled by tier, not by severity'() {
    // An advisory's severity is confidence that something is absent. Printing
    // "CRITICAL" for a guess is exactly the claim inflation the tiers exist to
    // prevent.
    const [label] = inlineLabels([
      finding({ tier: 'advisory', severity: 4, rule_id: 'CS011', title: 'No rate limiting' }),
    ]);
    assert.strictEqual(label.text, 'ADVISORY CS011: No rate limiting');
    assert.strictEqual(label.kind, 'advisory');
  },

  'findings on one line collapse to the worst plus a count'() {
    const labels = inlineLabels([
      finding({ line: 7, severity: 2, severity_label: 'medium', rule_id: 'CS004' }),
      finding({ line: 7, severity: 4, rule_id: 'CS002', title: 'SQL query built by string construction' }),
      finding({ line: 7, tier: 'advisory', severity: 4, rule_id: 'CS012' }),
    ]);
    assert.strictEqual(labels.length, 1);
    assert.ok(labels[0].text.startsWith('CRITICAL CS002:'), labels[0].text);
    assert.ok(labels[0].text.endsWith('(+2 more)'), labels[0].text);
  },

  'a deterministic finding outranks a higher-severity advisory'() {
    const [label] = inlineLabels([
      finding({ line: 3, tier: 'advisory', severity: 4, rule_id: 'CS010' }),
      finding({ line: 3, severity: 2, severity_label: 'medium', rule_id: 'CS004' }),
    ]);
    assert.ok(label.text.startsWith('MEDIUM CS004:'), label.text);
  },

  'ordering is by line and stable'() {
    const labels = inlineLabels([
      finding({ line: 9 }),
      finding({ line: 2 }),
      finding({ line: 5 }),
    ]);
    assert.deepStrictEqual(labels.map((l) => l.line), [2, 5, 9]);
  },

  'truncate leaves short text alone'() {
    assert.strictEqual(truncate('short', 50), 'short');
    assert.strictEqual(truncate('abcdef', 4), 'abc…');
  },

  'severity 3 is a warning, not a critical'() {
    assert.strictEqual(kindFor(finding({ severity: 3, severity_label: 'high' })), 'warning');
    assert.strictEqual(kindFor(finding({ severity: 4 })), 'critical');
  },

  'no findings means no labels'() {
    assert.deepStrictEqual(inlineLabels([]), []);
  },

  'every contributed setting is actually read'() {
    // A setting lives in two files: package.json declares it and config.ts
    // reads it. Adding it to one and forgetting the other gives a switch in
    // the Settings UI that does nothing - which is worse than no switch,
    // because the user believes they turned something off.
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
    );
    const config = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'utils', 'config.ts'),
      'utf8'
    );
    const declared = Object.keys(pkg.contributes.configuration.properties)
      .map((k) => k.replace(/^codesentinel\./, ''));
    const unread = declared.filter((k) => !config.includes(`'${k}'`));
    assert.deepStrictEqual(unread, [], `declared but never read: ${unread.join(', ')}`);
  },

  'every command is declared in package.json'() {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
    );
    const ext = fs.readFileSync(
      path.join(__dirname, '..', 'src', 'extension.ts'),
      'utf8'
    );
    const declared = new Set(pkg.contributes.commands.map((c) => c.command));
    const registered = [...ext.matchAll(/registerCommand\(\s*'([^']+)'/g)].map((m) => m[1]);
    const missing = registered.filter((c) => !declared.has(c));
    // The reverse also matters: a declared command with no handler shows up in
    // the palette and throws when chosen.
    const orphan = [...declared].filter((c) => !registered.includes(c));
    assert.deepStrictEqual(missing, [], `registered but not in the palette: ${missing}`);
    assert.deepStrictEqual(orphan, [], `in the palette but not registered: ${orphan}`);
  },
};

let failed = 0;
for (const [name, fn] of Object.entries(tests)) {
  try {
    fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`FAIL ${name}\n     ${err.message}`);
  }
}

if (failed > 0) {
  console.error(`\n${failed} inline-label test(s) failed`);
  process.exit(1);
}
console.log(`\n${Object.keys(tests).length} inline-label tests passed`);
