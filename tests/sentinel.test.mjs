import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { assert } from './test-utils.mjs';

function runNode(args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

function sentinelBin(root) {
  return path.join(root, 'node_modules', 'sentinel-lint', 'bin', 'sentinel-lint.mjs');
}

export async function setup(context) {
  context.scratch = path.join(context.root, '.tmp-test', 'sentinel');
  await fs.rm(context.scratch, { recursive: true, force: true });
  await fs.mkdir(context.scratch, { recursive: true });
}

export async function teardown(context) {
  if (context.scratch) await fs.rm(context.scratch, { recursive: true, force: true });
}

export const tests = [
  {
    name: 'sentinel-lint catches deliberate vulnerable fixture code and emits SARIF 2.1.0',
    async run(context) {
      const sarifPath = path.join(context.scratch, 'vulnerable.sarif');
      const result = await runNode([
        sentinelBin(context.root),
        'scan',
        path.join(context.root, 'fixtures', 'vulnerable-sample'),
        '--sarif',
        '--output',
        sarifPath,
        '--quiet',
        '--fail-on',
        'error'
      ], context.root);
      assert.equal(result.code, 1, result.stderr || result.stdout);
      const sarif = JSON.parse(await fs.readFile(sarifPath, 'utf8'));
      assert.equal(sarif.version, '2.1.0');
      assert.equal(Array.isArray(sarif.runs), true);
      assert.equal(sarif.runs.length, 1);
      const ruleIds = sarif.runs[0].results.map((entry) => entry.ruleId);
      assert.ok(ruleIds.includes('repo/child-process-injection'));
      assert.ok(ruleIds.includes('repo/dangerous-eval'));
      assert.ok(ruleIds.includes('repo/dangerous-html-sink'));
      assert.ok(sarif.runs[0].tool.driver.rules.length >= 15);
    }
  },
  {
    name: 'sentinel-lint vulnerable fixture scan reports real error findings',
    async run(context) {
      const result = await runNode([
        sentinelBin(context.root),
        'scan',
        path.join(context.root, 'fixtures', 'vulnerable-sample'),
        '--json',
        '--quiet',
        '--fail-on',
        'error'
      ], context.root);
      assert.equal(result.code, 1, result.stderr || result.stdout);
      const report = JSON.parse(result.stdout);
      assert.equal(report.summary.filesScanned, 1);
      assert.ok(report.summary.findings >= 3);
      const errors = report.findings.filter((finding) => finding.severity === 'error' || finding.severity === 'critical');
      assert.ok(errors.length >= 3);
      assert.deepEqual(
        errors.map((finding) => finding.ruleId).sort(),
        ['repo/child-process-injection', 'repo/dangerous-eval', 'repo/dangerous-html-sink'].sort()
      );
    }
  },
  {
    name: 'sentinel-lint scans the hardened server source with zero error or critical findings',
    async run(context) {
      const result = await runNode([
        sentinelBin(context.root),
        'scan',
        path.join(context.root, 'src'),
        '--json',
        '--quiet',
        '--fail-on',
        'error'
      ], context.root);
      assert.equal(result.code, 0, result.stderr || result.stdout);
      const report = JSON.parse(result.stdout);
      assert.equal(report.summary.filesScanned, 3);
      const blocking = report.findings.filter((finding) => finding.severity === 'error' || finding.severity === 'critical');
      assert.deepEqual(blocking, []);
    }
  },
  {
    name: 'sentinel-lint SARIF has stable locations and partial fingerprints',
    async run(context) {
      const sarifPath = path.join(context.scratch, 'fingerprints.sarif');
      const result = await runNode([
        sentinelBin(context.root),
        'scan',
        path.join(context.root, 'fixtures', 'vulnerable-sample'),
        '--sarif',
        '--output',
        sarifPath,
        '--quiet',
        '--fail-on',
        'error'
      ], context.root);
      assert.equal(result.code, 1, result.stderr || result.stdout);
      const sarif = JSON.parse(await fs.readFile(sarifPath, 'utf8'));
      for (const entry of sarif.runs[0].results) {
        assert.ok(entry.partialFingerprints, 'every SARIF result has partialFingerprints');
        assert.ok(entry.locations?.[0]?.physicalLocation?.artifactLocation?.uri, 'every SARIF result has a file URI');
        assert.ok(Number.isInteger(entry.locations[0].physicalLocation.region.startLine));
      }
    }
  }
];
