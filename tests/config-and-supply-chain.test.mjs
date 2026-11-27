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

const DEV_ROOT_PACKAGES = Object.freeze(['fast-check', 'sentinel-lint']);

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

function packageNameFromLockKey(key) {
  const parts = key.split('/');
  return key.includes('node_modules/@') ? parts.slice(-2).join('/') : parts.at(-1);
}

function installedLockKeys(lock) {
  return Object.keys(lock.packages || {}).filter((key) => key.startsWith('node_modules/')).sort();
}

function developmentClosure(lock) {
  const keys = installedLockKeys(lock);
  const byName = new Map(keys.map((key) => [packageNameFromLockKey(key), key]));
  const closure = new Set();
  const queue = [...DEV_ROOT_PACKAGES];
  while (queue.length > 0) {
    const name = queue.shift();
    if (closure.has(name)) continue;
    closure.add(name);
    const key = byName.get(name);
    if (!key) continue;
    queue.push(...Object.keys(lock.packages[key].dependencies || {}));
  }
  return closure;
}

function expectedInstalledNames(lock) {
  const devClosure = developmentClosure(lock);
  return {
    devClosure,
    names: new Set([...RUNTIME_PACKAGES, ...devClosure])
  };
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
    name: 'package manifest contains exactly the seventeen runtime libraries and keeps fuzz tooling development-only',
    async run({ root }) {
      const manifest = readJson(path.join(root, 'package.json'));
      assert.deepEqual(Object.keys(manifest.dependencies || {}).sort(), [...RUNTIME_PACKAGES].sort());
      assert.deepEqual(Object.keys(manifest.devDependencies || {}).sort(), [...DEV_ROOT_PACKAGES].sort());
      assert.equal(Object.keys(manifest.dependencies || {}).length, 17);
      assert.equal(Object.keys(manifest.devDependencies || {}).length, DEV_ROOT_PACKAGES.length);
      for (const name of DEV_ROOT_PACKAGES) {
        assert.equal(manifest.dependencies[name], undefined, `${name} must stay development-only`);
      }
    }
  },
  {
    name: 'node_modules contains exactly the runtime packages plus the development-only closure',
    async run({ root }) {
      const names = installedPackageJsonPaths(root).map((file) => readJson(file).name).sort();
      const lock = readJson(path.join(root, 'package-lock.json'));
      const expected = expectedInstalledNames(lock);
      assert.deepEqual(names, [...expected.names].sort());
      assert.equal(names.length, expected.names.size);
      for (const name of DEV_ROOT_PACKAGES) assert.ok(expected.devClosure.has(name), `${name} is missing from the lockfile`);
    }
  },
  {
    name: 'package-lock records exactly the runtime packages plus the development-only closure for npm ci',
    async run({ root }) {
      const lock = readJson(path.join(root, 'package-lock.json'));
      assert.equal(lock.lockfileVersion, 3);
      const installed = installedLockKeys(lock);
      const expected = expectedInstalledNames(lock);
      assert.equal(installed.length, expected.names.size);
      const names = installed.map(packageNameFromLockKey).sort();
      assert.deepEqual(names, [...expected.names].sort());
      assert.deepEqual(Object.keys(lock.packages[''].dependencies || {}).sort(), [...RUNTIME_PACKAGES].sort());
      assert.deepEqual(Object.keys(lock.packages[''].devDependencies || {}).sort(), [...DEV_ROOT_PACKAGES].sort());
    }
  },
  {
    name: 'runtime security packages are zero dependency and development packages stay outside the runtime closure',
    async run({ root }) {
      const lock = readJson(path.join(root, 'package-lock.json'));
      const installedKeys = installedLockKeys(lock);
      const expected = expectedInstalledNames(lock);
      const manifests = new Map(installedPackageJsonPaths(root).map((file) => {
        const manifest = readJson(file);
        return [manifest.name, manifest];
      }));
      for (const key of installedKeys) {
        const entry = lock.packages[key];
        const name = packageNameFromLockKey(key);
        if (RUNTIME_PACKAGES.includes(name)) {
          assert.deepEqual(entry.dependencies || {}, {}, `${key} must not have runtime dependencies`);
          assert.deepEqual(manifests.get(name).dependencies || {}, {}, `${name} must not have runtime dependencies`);
        } else {
          assert.ok(expected.devClosure.has(name), `${name} is outside the development-only closure`);
        }
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
      const lock = readJson(path.join(root, 'package-lock.json'));
      const expected = expectedInstalledNames(lock);
      const topLevel = fs.readdirSync(path.join(root, 'node_modules'), { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && !entry.name.startsWith('.'))
        .map((entry) => entry.name)
        .sort();
      const expectedTopLevel = new Set([...expected.names].map((name) => name.startsWith('@') ? name.split('/')[0] : name));
      assert.deepEqual(topLevel, [...expectedTopLevel].sort());
      for (const packageJson of installedPackageJsonPaths(root)) {
        const nested = path.join(path.dirname(packageJson), 'node_modules');
        assert.equal(fs.existsSync(nested), false, `${nested} should not exist`);
      }
    }
  }

];
