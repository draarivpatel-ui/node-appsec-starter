import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import fc from 'fast-check';

import { loadConfig } from '../src/config.mjs';
import { createSecurityToolkit } from '../src/security.mjs';

const ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SECRET_ALPHABET = ALPHA_NUM + '-_';
const LABEL_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'.split('');

function stringFrom(chars, minLength, maxLength) {
  return fc.array(fc.constantFrom(...chars.split('')), { minLength, maxLength }).map((items) => items.join(''));
}

function deterministicSecret(offset) {
  return Array.from({ length: 48 }, (_, index) => SECRET_ALPHABET[(index * 17 + offset) % SECRET_ALPHABET.length]).join('');
}

function hasUnsafeOutputChar(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
    if (code >= 0xd800 && code <= 0xdfff) return true;
    if (code === 0x2028 || code === 0x2029) return true;
  }
  return false;
}

const segment = stringFrom(ALPHA_NUM, 1, 12);
const relativePath = fc.array(segment, { minLength: 1, maxLength: 4 }).map((parts) => parts.join('/'));
const hostLabel = fc.array(fc.constantFrom(...LABEL_CHARS), { minLength: 1, maxLength: 10 }).map((items) => items.join(''));

let root;
let toolkit;

before(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'appsec-starter-fuzz-'));
  const config = loadConfig({
    NODE_ENV: 'test',
    SESSION_SECRET: deterministicSecret(1),
    CSRF_SECRET: deterministicSecret(7),
    WEBHOOK_SECRET: deterministicSecret(13),
    JWT_SECRET: deterministicSecret(19)
  });
  toolkit = createSecurityToolkit(config, { fixtureRoot: root, logWriter: () => {} });
});

after(async () => {
  if (root) await fs.rm(root, { recursive: true, force: true });
});

test('positive: benign file names resolve inside the sandbox', () => {
  fc.assert(fc.property(relativePath, (input) => {
    const resolved = toolkit.files.resolve(input);
    assert.doesNotThrow(() => toolkit.files.assertInside(resolved));
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: direct and encoded traversal never resolves inside the sandbox', () => {
  const prefix = fc.constantFrom('../', '../../', '%2e%2e/', '%252e%252e/x/', '..%2f');
  fc.assert(fc.property(prefix, relativePath, (hostilePrefix, tail) => {
    assert.throws(() => toolkit.files.resolve(hostilePrefix + tail), /ERR_PATHCAGE/);
  }), { seed: 20261127, numRuns: 100 });
});

test('positive: public HTTPS URLs pass the server SSRF policy', () => {
  fc.assert(fc.property(hostLabel, segment, (label, urlPath) => {
    const input = 'https://app' + label + '.example.com/' + urlPath;
    const result = toolkit.url.validate(input);
    assert.equal(result.ok, true);
    assert.equal(result.port, 443);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: loopback, metadata and non-HTTPS URLs fail the server SSRF policy', () => {
  const hostile = fc.oneof(
    fc.constant('https://127.0.0.1/'),
    fc.constant('https://169.254.169.254/'),
    fc.constant('https://10.0.0.1/'),
    fc.constant('https://100.64.0.1/'),
    hostLabel.map((label) => 'http://app' + label + '.example.com/'),
    hostLabel.map((label) => 'https://user:pass@app' + label + '.example.com/')
  );
  fc.assert(fc.property(hostile, (input) => {
    const result = toolkit.url.validate(input);
    assert.equal(result.ok, false);
    assert.ok(['PRIVATE_IP', 'UNSAFE_SCHEME', 'USERINFO_FORBIDDEN'].includes(result.code));
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: hostile log input is neutralized into one credential-free NDJSON line', () => {
  const attack = fc.constantFrom('\n', '\r', '\u2028', '\u001b[31m', '\u202e');
  const token = fc.array(fc.integer({ min: 0, max: ALPHA_NUM.length - 1 }), { minLength: 24, maxLength: 32 })
    .map((indexes) => indexes.map((value, index) => ALPHA_NUM[(value + index * 17) % ALPHA_NUM.length]).join(''));
  fc.assert(fc.property(fc.string({ maxLength: 60 }), attack, token, (before, hostile, credential) => {
    const line = toolkit.log.json('info', before + hostile, {
      authorization: 'Bearer ' + credential
    }, {
      timestamp: '2026-01-01T00:00:00.000Z'
    });
    assert.equal(hasUnsafeOutputChar(line), false);
    assert.equal(line.includes(credential), false);
    assert.doesNotThrow(() => JSON.parse(line));
  }), { seed: 20261127, numRuns: 100 });
});
