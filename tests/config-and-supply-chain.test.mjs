import fs from 'node:fs';
import path from 'node:path';
import { assert, makeTestEnv } from './test-utils.mjs';
import { loadConfig } from '../src/config.mjs';

const RUNTIME_PACKAGES = Object.freeze([
  'pathcage',
  'headersafe',
  'redirectcage',
  'envcage',
  'cookiecage',
  'zipcage',
  'logcage',
  'corscage',
  'jsoncage',
  '@aarivbuildz/hookverify',
  '@aarivbuildz/jwtguard',
  '@aarivbuildz/csrfshield',
  '@aarivbuildz/urlguard',
  '@aarivbuildz/csvshield',
  '@aarivbuildz/htmlclean',
  '@aarivbuildz/regex-shield',
  '@aarivbuildz/secretsweep'
]);

const ALL_PACKAGES = Object.freeze([...RUNTIME_PACKAGES, 'sentinel-lint']);

const EXPECTED_EXPORTS = Object.freeze({
  pathcage: ['createCage', 'resolveSafePath'],
  headersafe: ['applySecurityHeaders', 'buildSecurityHeaders'],
  redirectcage: ['createRedirectGuard', 'assertSafeRedirect'],
  envcage: ['defineEnv', 't', 'safeSnapshot', 'SecretString'],
  cookiecage: ['serializeCookie', 'signCookieValue', 'verifyCookieValue', 'parseCookieHeader'],
  zipcage: ['assertSafeZipBuffer', 'inspectZipBuffer', 'createZipBuffer'],
  logcage: ['createLogCage', 'formatSafeJsonLog'],
  corscage: ['createNodeCorsMiddleware', 'createCorsPolicy'],
  jsoncage: ['createJsonCage', 'parseSafeJson', 'stringifySafeJson'],
  '@aarivbuildz/hookverify': ['createVerifier', 'MemoryReplayStore', 'verify'],
  '@aarivbuildz/jwtguard': ['signJwt', 'verifyJwt'],
  '@aarivbuildz/urlguard': ['createGuard', 'validateUrl'],
  '@aarivbuildz/csvshield': ['stringifySafeCsv', 'sanitizeCell'],
  '@aarivbuildz/htmlclean': ['createSanitizer', 'sanitizeHtml', 'PROSE_POLICY'],
  '@aarivbuildz/regex-shield': ['assertSafeRegex', 'analyzeRegex'],
  '@aarivbuildz/secretsweep': ['scanText'],
  'sentinel-lint': ['scan', 'formatSarif', 'SARIF_VERSION']
});

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function installedPackageJsonPaths(root) {
  const nodeModules = path.join(root, 'node_modules');
  const output = [];
  for (const entry of fs.readdirSync(nodeModules, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    if (entry.name.startsWith('@')) {
      const scopeDir = path.join(nodeModules, entry.name);
      for (const scoped of fs.readdirSync(scopeDir, { withFileTypes: true })) {
        if (scoped.isDirectory()) output.push(path.join(scopeDir, scoped.name, 'package.json'));
      }
    } else {
      output.push(path.join(nodeModules, entry.name, 'package.json'));
    }
  }
  return output.sort();
}

export const tests = [
  {
    name: 'envcage validates config and redacts every secret',
    async run() {
      const env = makeTestEnv();
      const config = loadConfig(env);
      assert.equal(config.NODE_ENV, 'test');
      assert.equal(config.PORT, 8080);
      assert.equal(config.SESSION_SECRET.reveal(), env.SESSION_SECRET);
      assert.equal(String(config.SESSION_SECRET), '[REDACTED]');
      assert.equal(config.snapshot.SESSION_SECRET, '[REDACTED]');
      assert.equal(config.snapshot.CSRF_SECRET, '[REDACTED]');
      assert.equal(config.snapshot.WEBHOOK_SECRET, '[REDACTED]');
      assert.equal(config.snapshot.JWT_SECRET, '[REDACTED]');
      assert.deepEqual(config.ALLOWED_ORIGINS, ['http://127.0.0.1:8080', 'http://localhost:8080']);
    }
  },
  {
    name: 'production config fails closed when secrets are missing',
    async run() {
      assert.throws(
        () => loadConfig({ NODE_ENV: 'production' }),
        (error) => error && String(error.code || '').startsWith('ERR_ENVCAGE')
      );
    }
  },
  {
    name: 'package manifest contains exactly the seventeen runtime libraries and sentinel lint as the only dev dependency',
    async run({ root }) {
      const manifest = readJson(path.join(root, 'package.json'));
      assert.deepEqual(Object.keys(manifest.dependencies || {}).sort(), [...RUNTIME_PACKAGES].sort());
      assert.deepEqual(Object.keys(manifest.devDependencies || {}), ['sentinel-lint']);
      assert.equal(Object.keys(manifest.dependencies || {}).length, 17);
      assert.equal(Object.keys(manifest.devDependencies || {}).length, 1);
    }
  },
  {
    name: 'node_modules contains exactly the eighteen expected package directories',
    async run({ root }) {
      const names = installedPackageJsonPaths(root).map((file) => readJson(file).name).sort();
      assert.deepEqual(names, [...ALL_PACKAGES].sort());
      assert.equal(names.length, 18);
    }
  },
  {
    name: 'package-lock records exactly the eighteen installed packages for npm ci',
    async run({ root }) {
      const lock = readJson(path.join(root, 'package-lock.json'));
      assert.equal(lock.lockfileVersion, 3);
      const installed = Object.keys(lock.packages || {}).filter((key) => key.startsWith('node_modules/')).sort();
      assert.equal(installed.length, 18);
      const names = installed.map((key) => {
        const parts = key.split('/');
        return key.includes('node_modules/@') ? `${parts.at(-2)}/${parts.at(-1)}` : parts.at(-1);
      }).sort();
      assert.deepEqual(names, [...ALL_PACKAGES].sort());
      assert.deepEqual(Object.keys(lock.packages[''].dependencies || {}).sort(), [...RUNTIME_PACKAGES].sort());
      assert.deepEqual(Object.keys(lock.packages[''].devDependencies || {}), ['sentinel-lint']);
    }
  },
  {
    name: 'all eighteen packages are zero dependency at runtime with no transitive third-party bloat',
    async run({ root }) {
      const lock = readJson(path.join(root, 'package-lock.json'));
      const installedKeys = Object.keys(lock.packages || {}).filter((key) => key.startsWith('node_modules/'));
      for (const key of installedKeys) {
        const entry = lock.packages[key];
        assert.deepEqual(entry.dependencies || {}, {}, `${key} must not have runtime dependencies`);
      }
      for (const packageJson of installedPackageJsonPaths(root)) {
        const manifest = readJson(packageJson);
        assert.deepEqual(manifest.dependencies || {}, {}, `${manifest.name} must not have runtime dependencies`);
      }
    }
  },
  {
    name: 'installed packages expose the verified live APIs used by the server',
    async run() {
      for (const [specifier, exportsRequired] of Object.entries(EXPECTED_EXPORTS)) {
        const module = await import(specifier);
        for (const exportName of exportsRequired) {
          assert.ok(module[exportName] !== undefined, `${specifier} is missing export ${exportName}`);
        }
      }
      const nodeEntry = await import('@aarivbuildz/csrfshield/node');
      assert.equal(typeof nodeEntry.createShield, 'function');
      assert.equal(typeof nodeEntry.nodeCrypto.randomBytes, 'function');
    }
  },
  {
    name: 'node_modules contains no unexpected top-level package scopes or nested dependency trees',
    async run({ root }) {
      const topLevel = fs.readdirSync(path.join(root, 'node_modules'), { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && !entry.name.startsWith('.'))
        .map((entry) => entry.name)
        .sort();
      assert.deepEqual(topLevel, [
        '@aarivbuildz',
        'cookiecage',
        'corscage',
        'envcage',
        'headersafe',
        'jsoncage',
        'logcage',
        'pathcage',
        'redirectcage',
        'sentinel-lint',
        'zipcage'
      ].sort());
      for (const packageJson of installedPackageJsonPaths(root)) {
        const nested = path.join(path.dirname(packageJson), 'node_modules');
        assert.equal(fs.existsSync(nested), false, `${nested} should not exist`);
      }
    }
  }
];
