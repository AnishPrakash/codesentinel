#!/usr/bin/env node
/**
 * Verifies the contract between the extension and the CLI.
 *
 * The extension's whole design rests on `python -m codesentinel scan --format json`
 * returning a specific shape. This script spawns it exactly the way scanner.ts
 * does and asserts every field the extension reads actually arrives. Run it
 * after changing either side.
 *
 *   node vscode-extension/scripts/verify-bridge.js [pythonPath]
 */
const { spawn } = require('child_process');
const path = require('path');

const python = process.argv[2] || process.env.PYTHON || 'python';
const repoRoot = path.resolve(__dirname, '..', '..');
const target = process.argv[3] || path.join(repoRoot, 'demo');

const REQUIRED_FINDING_FIELDS = [
  'rule_id',
  'title',
  'severity',
  'severity_label',
  'cwe',
  'owasp',
  'line',
  'end_line',
  'column',
  'snippet',
  'language',
  'tier',
  'explanation',
  'attack',
  'fix',
  'question',
  'confidence',
];

function fail(message) {
  console.error(`FAIL  ${message}`);
  process.exitCode = 1;
}

function ok(message) {
  console.log(`ok    ${message}`);
}

const child = spawn(
  python,
  ['-m', 'codesentinel', 'scan', target, '--format', 'json', '--no-ledger'],
  { cwd: repoRoot, env: { ...process.env, PYTHONIOENCODING: 'utf-8', NO_COLOR: '1' } }
);

let stdout = '';
let stderr = '';
child.stdout.on('data', (d) => (stdout += d.toString()));
child.stderr.on('data', (d) => (stderr += d.toString()));

child.on('error', (err) => {
  fail(`could not spawn "${python} -m codesentinel": ${err.message}`);
  process.exit(1);
});

child.on('close', (code) => {
  if (code !== 0 && code !== 1) {
    fail(`exit code ${code}\n${stderr}`);
    process.exit(1);
  }
  ok(`exit code ${code} (0 = clean, 1 = findings; both are successful scans)`);

  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start === -1 || end === -1) {
    fail('no JSON object in stdout');
    process.exit(1);
  }

  let report;
  try {
    report = JSON.parse(stdout.slice(start, end + 1));
  } catch (err) {
    fail(`stdout is not valid JSON: ${err.message}`);
    process.exit(1);
  }
  ok('stdout parses as JSON');

  for (const key of ['files', 'coverage', 'stats']) {
    if (!(key in report)) {
      fail(`report is missing "${key}"`);
    }
  }
  ok('report has files, coverage, stats');

  if (!report.coverage.includes('not a security audit')) {
    fail('coverage statement missing its scope disclaimer');
  } else {
    ok('coverage statement present');
  }

  const files = report.files.filter((f) => f.findings.length > 0);
  if (files.length === 0) {
    fail('expected findings on the demo files');
    process.exit(1);
  }
  ok(`${files.length} file(s) with findings, ${report.stats.findings} total`);

  const languages = new Set(files.map((f) => f.language));
  for (const want of ['python', 'javascript', 'java']) {
    if (!languages.has(want)) {
      fail(`no ${want} file in the report - is that language wired up?`);
    }
  }
  ok(`languages present: ${[...languages].sort().join(', ')}`);

  const file = files[0];
  const allFindings = files.flatMap((f) => f.findings);

  for (const f of allFindings) {
    for (const field of REQUIRED_FINDING_FIELDS) {
      if (!(field in f)) {
        fail(`finding ${f.rule_id} is missing "${field}"`);
      }
    }
    if (f.tier !== 'deterministic' && f.tier !== 'advisory') {
      fail(`finding ${f.rule_id} has an unknown tier "${f.tier}"`);
    }
    if (!String(f.cwe).startsWith('CWE-')) {
      fail(`finding ${f.rule_id} has no CWE`);
    }
  }
  ok('every finding carries all fields the extension reads');

  const gated = allFindings.filter((f) => f.question);
  if (gated.length === 0) {
    fail('no finding is gated - the comprehension gate is not reaching the editor');
  } else {
    ok(`${gated.length} finding(s) gated behind a comprehension question`);
  }

  if (stdout.includes('AKIAIOSFODNN7EXAMPLE')) {
    fail('an unredacted credential reached the JSON output');
  } else {
    ok('credentials are redacted in the JSON output');
  }

  const tiers = new Set(allFindings.map((f) => f.tier));
  ok(`tiers present: ${[...tiers].join(', ')}`);

  console.log(
    process.exitCode ? '\nBridge contract BROKEN.' : '\nBridge contract holds.'
  );
});
