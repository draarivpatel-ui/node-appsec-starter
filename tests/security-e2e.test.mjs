import fs from 'node:fs/promises';
import path from 'node:path';
import { createZipBuffer } from 'zipcage';
import { createApp } from '../src/server.mjs';
import {
  assert,
  attackJson,
  cookieHeader,
  fetchJson,
  fetchText,
  getSetCookies,
  githubSignature,
  makeTestEnv,
  postJson,
  updateCookieJar
} from './test-utils.mjs';

function depthPayload(depth) {
  let value = '1';
  for (let index = 0; index < depth; index += 1) {
    value = `[${value}]`;
  }
  return value;
}

async function postZip(baseUrl, bytes) {
  return fetchJson(baseUrl, '/api/inspect-zip', {
    method: 'POST',
    headers: { 'content-type': 'application/zip' },
    body: bytes
  });
}

export async function setup(context) {
  const scratch = path.join(context.root, '.tmp-test', 'e2e');
  await fs.rm(scratch, { recursive: true, force: true });
  const fixtureRoot = path.join(scratch, 'files');
  const outsideRoot = path.join(scratch, 'outside');
  await fs.mkdir(fixtureRoot, { recursive: true });
  await fs.mkdir(outsideRoot, { recursive: true });
  await fs.cp(path.join(context.root, 'fixtures', 'files'), fixtureRoot, { recursive: true });
  await fs.writeFile(path.join(outsideRoot, 'outside-secret.txt'), 'outside the sandbox\n', 'utf8');
  await fs.symlink(outsideRoot, path.join(fixtureRoot, 'linked-outside'), process.platform === 'win32' ? 'junction' : 'dir');

  context.scratch = scratch;
  context.env = makeTestEnv();
  context.configuredOrigin = 'http://127.0.0.1:8080';
  context.logs = [];
  context.jar = new Map();
  context.app = createApp({
    env: context.env,
    fixtureRoot,
    logWriter: (line) => context.logs.push(line)
  });
  const started = await context.app.listen('127.0.0.1', 0);
  context.baseUrl = `http://127.0.0.1:${started.address.port}`;
}

export async function teardown(context) {
  if (context.app) await context.app.close();
  if (context.scratch) await fs.rm(context.scratch, { recursive: true, force: true });
}

export const tests = [
  {
    name: 'health endpoint returns strict headersafe security headers',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/health');
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
      assert.equal(response.headers.get('x-frame-options'), 'DENY');
      assert.match(response.headers.get('strict-transport-security') || '', /max-age=31536000/);
      assert.match(response.headers.get('permissions-policy') || '', /geolocation=\(\)/);
      assert.match(response.headers.get('content-security-policy') || '', /default-src 'none'/);
    }
  },
  {
    name: 'corscage reflects only the configured origin on an actual request',
    async run(context) {
      const { response } = await fetchJson(context.baseUrl, '/health', {
        headers: { origin: context.configuredOrigin }
      });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('access-control-allow-origin'), context.configuredOrigin);
      assert.match(response.headers.get('vary') || '', /Origin/i);
    }
  },
  {
    name: 'corscage omits access control headers for an evil actual origin',
    async run(context) {
      const { response } = await fetchJson(context.baseUrl, '/health', {
        headers: { origin: 'https://evil.example' }
      });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('access-control-allow-origin'), null);
      assert.match(response.headers.get('vary') || '', /Origin/i);
    }
  },
  {
    name: 'corscage authorizes a hardened preflight for the configured origin',
    async run(context) {
      const response = await fetch(new URL('/api/json', context.baseUrl), {
        method: 'OPTIONS',
        headers: {
          origin: context.configuredOrigin,
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type'
        }
      });
      await response.arrayBuffer();
      assert.equal(response.status, 204);
      assert.equal(response.headers.get('access-control-allow-origin'), context.configuredOrigin);
      assert.match(response.headers.get('access-control-allow-methods') || '', /POST/);
      assert.match((response.headers.get('access-control-allow-headers') || '').toLowerCase(), /content-type/);
    }
  },
  {
    name: 'corscage rejects a preflight from an evil origin',
    async run(context) {
      const response = await fetch(new URL('/api/json', context.baseUrl), {
        method: 'OPTIONS',
        headers: {
          origin: 'https://evil.example',
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type'
        }
      });
      await response.arrayBuffer();
      assert.equal(response.status, 403);
      assert.equal(response.headers.get('access-control-allow-origin'), null);
    }
  },
  {
    name: 'logcage writes one redacted NDJSON line per request',
    async run(context) {
      const marker = 'Z9xY8wV7uT6sR5qP4nM3kJ2hG1fD0sA9';
      const cookieMarker = 'Q8wE7rT6yU5iO4pA3sD2fG1hJ9kL0zX';
      const before = context.logs.length;
      const { response } = await fetchJson(context.baseUrl, '/health', {
        headers: {
          authorization: `Bearer ${marker}`,
          cookie: `demo=${cookieMarker}`
        }
      });
      assert.equal(response.status, 200);
      await new Promise((resolve) => setImmediate(resolve));
      assert.ok(context.logs.length > before);
      const line = context.logs.at(-1);
      assert.equal(line.includes('\n'), false);
      assert.equal(line.includes('\r'), false);
      const parsed = JSON.parse(line);
      assert.equal(parsed.msg, 'http request');
      assert.equal(parsed.meta.headers.authorization, '[REDACTED]');
      assert.equal(parsed.meta.headers.cookie, '[REDACTED]');
      assert.equal(line.includes(marker), false);
      assert.equal(line.includes(cookieMarker), false);
    }
  },
  {
    name: 'jsoncage accepts a benign strict JSON object',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/json', {
        user: { name: 'Ada', roles: ['editor'] },
        active: true
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.deepEqual(body.json.keys, ['active', 'user']);
      assert.equal(body.json.keyCount, 2);
    }
  },
  {
    name: 'jsoncage blocks prototype pollution keys',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/json', '{"__proto__":{"isAdmin":true}}');
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'JSONCAGE_PROTOTYPE_KEY');
    }
  },
  {
    name: 'jsoncage blocks duplicate key smuggling',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/json', '{"role":"user","role":"admin"}');
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'JSONCAGE_DUPLICATE_KEY');
    }
  },
  {
    name: 'jsoncage blocks recursive depth bombs',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/json', depthPayload(30));
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'JSONCAGE_MAX_DEPTH');
    }
  },
  {
    name: 'pathcage serves a benign file inside the sandbox',
    async run(context) {
      const { response, text } = await fetchText(context.baseUrl, '/api/files?name=hello.txt');
      assert.equal(response.status, 200);
      assert.match(text, /pathcage sandbox/);
    }
  },
  {
    name: 'pathcage serves a nested benign file inside the sandbox',
    async run(context) {
      const { response, text } = await fetchText(context.baseUrl, '/api/files?name=docs/readme.txt');
      assert.equal(response.status, 200);
      assert.match(text, /without leaving the sandbox/);
    }
  },
  {
    name: 'pathcage blocks direct parent traversal',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/files?name=../secret.txt');
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_PATHCAGE_TRAVERSAL');
    }
  },
  {
    name: 'pathcage blocks encoded parent traversal layers',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/files?name=%252e%252e%252fsecret.txt');
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_PATHCAGE_ENCODED_TRAVERSAL');
    }
  },
  {
    name: 'pathcage blocks NUL byte path injection',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/files?name=hello%00.txt');
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_PATHCAGE_NULL_BYTE');
    }
  },
  {
    name: 'pathcage blocks symlink escapes outside the fixture root',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/files?name=linked-outside/outside-secret.txt');
      assert.equal(response.status, 400);
      assert.match(attackJson(body) || '', /^ERR_PATHCAGE_(FORBIDDEN_SYMLINK|SYMLINK_ESCAPE)/);
    }
  },
  {
    name: 'pathcage returns 404 for a missing in-scope file',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/files?name=missing.txt');
      assert.equal(response.status, 404);
      assert.equal(attackJson(body), 'ERR_FILE_NOT_FOUND');
    }
  },
  {
    name: 'pathcage blocks absolute paths',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/files?name=%2Fetc%2Fpasswd');
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_PATHCAGE_ABSOLUTE_PATH');
    }
  },
  {
    name: 'redirectcage permits a safe relative redirect',
    async run(context) {
      const response = await fetch(new URL('/api/redirect?next=%2Fsettings%3Ftab%3Dsecurity', context.baseUrl), { redirect: 'manual' });
      await response.arrayBuffer();
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), '/settings?tab=security');
    }
  },
  {
    name: 'redirectcage permits an exactly allowlisted absolute origin',
    async run(context) {
      const target = encodeURIComponent('http://127.0.0.1:8080/account');
      const response = await fetch(new URL(`/api/redirect?next=${target}`, context.baseUrl), { redirect: 'manual' });
      await response.arrayBuffer();
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), 'http://127.0.0.1:8080/account');
    }
  },
  {
    name: 'redirectcage blocks protocol-relative external redirects',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, `/api/redirect?next=${encodeURIComponent('//evil.example/phish')}`);
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_REDIRECTCAGE_PROTOCOL_RELATIVE');
    }
  },
  {
    name: 'redirectcage blocks javascript scheme redirects',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, `/api/redirect?next=${encodeURIComponent('javascript:alert(1)')}`);
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_REDIRECTCAGE_DANGEROUS_SCHEME');
    }
  },
  {
    name: 'redirectcage blocks CRLF redirect header injection',
    async run(context) {
      const malicious = encodeURIComponent('/ok\r\nLocation: https://evil.example');
      const { response, body } = await fetchJson(context.baseUrl, `/api/redirect?next=${malicious}`);
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_REDIRECTCAGE_CONTROL_CHARACTER');
    }
  },
  {
    name: 'redirectcage blocks dot-segment traversal instead of normalizing it',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, `/api/redirect?next=${encodeURIComponent('/account/../admin')}`);
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_REDIRECTCAGE_DOT_SEGMENT');
    }
  },
  {
    name: 'session creation signs a hardened cookie and issues a csrf double-submit token',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/session', { method: 'POST' });
      assert.equal(response.status, 201);
      assert.equal(body.ok, true);
      assert.equal(body.session.authenticated, true);
      assert.equal(typeof body.csrf.token, 'string');
      assert.ok(body.csrf.token.length > 30);
      const setCookies = getSetCookies(response);
      assert.equal(setCookies.length, 2);
      const sessionSetCookie = setCookies.find((value) => value.startsWith('__Host-session='));
      const csrfSetCookie = setCookies.find((value) => value.startsWith('__Host-csrf='));
      assert.ok(sessionSetCookie);
      assert.ok(csrfSetCookie);
      assert.match(sessionSetCookie, /HttpOnly/);
      assert.match(sessionSetCookie, /Secure/);
      assert.match(sessionSetCookie, /SameSite=Strict/);
      assert.match(sessionSetCookie, /Path=\//);
      updateCookieJar(context.jar, setCookies);
      context.csrfToken = body.csrf.token;
    }
  },
  {
    name: 'session read rejects a missing signed cookie',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/session');
      assert.equal(response.status, 403);
      assert.equal(attackJson(body), 'ERR_SESSION_COOKIE_MISSING');
    }
  },
  {
    name: 'session read verifies cookiecage and jwtguard signatures',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/session', {
        headers: { cookie: cookieHeader(context.jar) }
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.session.authenticated, true);
      assert.equal(body.session.issuer, 'node-appsec-starter');
      assert.equal(body.session.audience, 'session');
      assert.equal(body.session.keyRotated, false);
      assert.equal(typeof body.csrf.token, 'string');
      updateCookieJar(context.jar, getSetCookies(response));
      context.csrfToken = body.csrf.token;
    }
  },
  {
    name: 'session read rejects a tampered signed cookie',
    async run(context) {
      const tampered = new Map(context.jar);
      const original = tampered.get('__Host-session');
      tampered.set('__Host-session', `${original.slice(0, -1)}${original.endsWith('A') ? 'B' : 'A'}`);
      const { response } = await fetchJson(context.baseUrl, '/api/session', {
        headers: { cookie: cookieHeader(tampered) }
      });
      assert.equal(response.status, 403);
    }
  },
  {
    name: 'session rotation without the csrf header is rejected',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/session', {
        method: 'POST',
        headers: {
          cookie: cookieHeader(context.jar),
          origin: context.configuredOrigin
        }
      });
      assert.equal(response.status, 403);
      assert.equal(attackJson(body), 'INVALID_TOKEN');
    }
  },
  {
    name: 'session rotation with a foreign origin is rejected',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/session', {
        method: 'POST',
        headers: {
          cookie: cookieHeader(context.jar),
          origin: 'https://evil.example',
          'x-csrf-token': context.csrfToken
        }
      });
      assert.equal(response.status, 403);
      assert.equal(attackJson(body), 'ORIGIN_MISMATCH');
    }
  },
  {
    name: 'session rotation succeeds with cookie, jwt, csrf token and allowed origin',
    async run(context) {
      const { response, body } = await fetchJson(context.baseUrl, '/api/session', {
        method: 'POST',
        headers: {
          cookie: cookieHeader(context.jar),
          origin: context.configuredOrigin,
          'x-csrf-token': context.csrfToken
        }
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.session.rotated, true);
      updateCookieJar(context.jar, getSetCookies(response));
      context.csrfToken = body.csrf.token;
    }
  },
  {
    name: 'hookverify accepts a correctly signed GitHub webhook',
    async run(context) {
      const raw = JSON.stringify({ delivery: 'valid-1', action: 'opened' });
      const { response, body } = await postJson(context.baseUrl, '/api/webhook', raw, {
        'x-hub-signature-256': githubSignature(raw, context.env.WEBHOOK_SECRET)
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.webhook.provider, 'github');
      assert.equal(body.webhook.valid, true);
      assert.equal(typeof body.webhook.replayKey, 'string');
    }
  },
  {
    name: 'hookverify rejects a mismatched webhook signature',
    async run(context) {
      const raw = JSON.stringify({ delivery: 'invalid-signature-1', action: 'opened' });
      const { response, body } = await postJson(context.baseUrl, '/api/webhook', raw, {
        'x-hub-signature-256': `sha256=${'0'.repeat(64)}`
      });
      assert.equal(response.status, 403);
      assert.equal(attackJson(body), 'SIGNATURE_MISMATCH');
    }
  },
  {
    name: 'hookverify rejects replay of an already verified delivery',
    async run(context) {
      const raw = JSON.stringify({ delivery: 'replay-1', action: 'opened' });
      const headers = { 'x-hub-signature-256': githubSignature(raw, context.env.WEBHOOK_SECRET) };
      const first = await postJson(context.baseUrl, '/api/webhook', raw, headers);
      assert.equal(first.response.status, 200);
      const second = await postJson(context.baseUrl, '/api/webhook', raw, headers);
      assert.equal(second.response.status, 403);
      assert.equal(attackJson(second.body), 'REPLAYED_DELIVERY');
    }
  },
  {
    name: 'urlguard accepts a benign public HTTPS preview URL without fetching it',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/fetch-preview', {
        url: 'https://example.com/docs?q=1'
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.url.hostname, 'example.com');
      assert.equal(body.url.fetched, false);
    }
  },
  {
    name: 'urlguard blocks the cloud metadata address',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/fetch-preview', {
        url: 'https://169.254.169.254/latest/meta-data'
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_URLGUARD_PRIVATE_IP');
      assert.equal(body.error.details.guardCode, 'PRIVATE_IP');
    }
  },
  {
    name: 'urlguard blocks private RFC1918 network targets',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/fetch-preview', {
        url: 'https://10.1.2.3/internal'
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_URLGUARD_PRIVATE_IP');
    }
  },
  {
    name: 'urlguard blocks loopback and non-HTTPS schemes',
    async run(context) {
      const loopback = await postJson(context.baseUrl, '/api/fetch-preview', { url: 'https://127.0.0.1/admin' });
      assert.equal(loopback.response.status, 400);
      assert.equal(attackJson(loopback.body), 'ERR_URLGUARD_PRIVATE_IP');
      const plainHttp = await postJson(context.baseUrl, '/api/fetch-preview', { url: 'http://example.com/' });
      assert.equal(plainHttp.response.status, 400);
      assert.equal(attackJson(plainHttp.body), 'ERR_URLGUARD_UNSAFE_SCHEME');
    }
  },
  {
    name: 'csvshield exports benign rows as safe CSV',
    async run(context) {
      const { response, text } = await postJson(context.baseUrl, '/api/export-csv', {
        rows: [
          { name: 'Ada', score: 42 },
          { name: 'Bob', score: 35 }
        ]
      });
      assert.equal(response.status, 200);
      assert.equal(text, 'name,score\nAda,42\nBob,35\n');
      assert.match(response.headers.get('content-type') || '', /text\/csv/);
    }
  },
  {
    name: 'csvshield rejects spreadsheet formula injection',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/export-csv', {
        rows: [{ name: 'Ada', formula: '=CMD|/c calc!A1' }]
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_CSV_FORMULA');
    }
  },
  {
    name: 'htmlclean accepts benign prose markup unchanged',
    async run(context) {
      const html = '<p>Hello <b>world</b></p>';
      const { response, body } = await postJson(context.baseUrl, '/api/render-bio', { html });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.html, html);
      assert.equal(body.changed, false);
    }
  },
  {
    name: 'htmlclean strict mode rejects script injection',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/render-bio', {
        html: '<p>Hello</p><script>alert(1)</script>'
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_HTMLCLEAN_ACTIVE_CONTENT');
      assert.equal(typeof body.error.details.sanitizedLength, 'number');
    }
  },
  {
    name: 'htmlclean strict mode rejects event handler and javascript URL injection',
    async run(context) {
      const eventResult = await postJson(context.baseUrl, '/api/render-bio', {
        html: '<img src="x" onerror="alert(1)">'
      });
      assert.equal(eventResult.response.status, 400);
      assert.equal(attackJson(eventResult.body), 'ERR_HTMLCLEAN_ACTIVE_CONTENT');
      const urlResult = await postJson(context.baseUrl, '/api/render-bio', {
        html: '<a href="javascript:alert(1)">click</a>'
      });
      assert.equal(urlResult.response.status, 400);
      assert.equal(attackJson(urlResult.body), 'ERR_HTMLCLEAN_ACTIVE_CONTENT');
    }
  },
  {
    name: 'regex-shield accepts a bounded search pattern',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/check-regex', {
        pattern: '^[a-z0-9_-]{3,32}$',
        flags: ''
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.regex.safe, true);
      assert.equal(body.regex.risk, 'safe');
      assert.equal(body.regex.worstCase, 'linear');
    }
  },
  {
    name: 'regex-shield blocks nested quantifier ReDoS',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/check-regex', {
        pattern: '(a+)+$',
        flags: ''
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_REGEX_REDOS_RISK');
      assert.equal(body.error.details.risk, 'critical');
      assert.equal(body.error.details.findings[0].rule, 'nested-quantifier');
    }
  },
  {
    name: 'regex-shield blocks overlapping alternation ReDoS',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/check-regex', {
        pattern: '^(a|aa)+$',
        flags: ''
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_REGEX_REDOS_RISK');
      assert.equal(body.error.details.findings[0].rule, 'overlapping-alternation-quantifier');
    }
  },
  {
    name: 'zipcage accepts a benign ZIP archive',
    async run(context) {
      const archive = createZipBuffer([{ name: 'hello.txt', data: 'hello', method: 'deflate' }]);
      const { response, body } = await postZip(context.baseUrl, archive);
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.zip.safe, true);
      assert.equal(body.zip.entries[0].name, 'hello.txt');
      assert.equal(body.zip.totals.files, 1);
    }
  },
  {
    name: 'zipcage blocks zip-slip traversal entries',
    async run(context) {
      const archive = createZipBuffer([{ name: '../evil.txt', data: 'evil' }], { validate: false });
      const { response, body } = await postZip(context.baseUrl, archive);
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_ZIPCAGE_PATH_TRAVERSAL');
    }
  },
  {
    name: 'zipcage blocks compression bombs by ratio',
    async run(context) {
      const archive = createZipBuffer([{ name: 'bomb.txt', data: '0'.repeat(200000), method: 'deflate' }], { validate: false });
      const { response, body } = await postZip(context.baseUrl, archive);
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_ZIPCAGE_RATIO_LIMIT');
    }
  },
  {
    name: 'secretsweep accepts a benign snippet',
    async run(context) {
      const { response, body } = await postJson(context.baseUrl, '/api/scan-snippet', {
        text: 'const greeting = "hello world";'
      });
      assert.equal(response.status, 200);
      assert.equal(body.ok, true);
      assert.equal(body.secrets.clean, true);
    }
  },
  {
    name: 'secretsweep blocks leaked secret material and returns only redacted findings',
    async run(context) {
      const secretValue = 'X7kQ9zW2vB5nM8pR4sT6uY3hJ1gF0dS9';
      const { response, text, body } = await postJson(context.baseUrl, '/api/scan-snippet', {
        text: `apiToken = "${secretValue}"`
      });
      assert.equal(response.status, 400);
      assert.equal(attackJson(body), 'ERR_SECRETSCAN_FINDINGS');
      assert.equal(body.error.details.findings.length > 0, true);
      assert.equal(body.error.details.findings[0].detector, 'generic-secret-assignment');
      assert.equal(body.error.details.findings[0].redacted.includes(secretValue), false);
      assert.match(body.error.details.findings[0].fingerprint, /^[a-f0-9]{64}$/);
      assert.equal(text.includes(secretValue), false);
    }
  },
  {
    name: 'unknown routes return 404 and wrong methods return 405',
    async run(context) {
      const missing = await fetchJson(context.baseUrl, '/api/not-real');
      assert.equal(missing.response.status, 404);
      assert.equal(attackJson(missing.body), 'ERR_NOT_FOUND');
      const wrongMethod = await fetchJson(context.baseUrl, '/api/json');
      assert.equal(wrongMethod.response.status, 405);
      assert.equal(attackJson(wrongMethod.body), 'ERR_METHOD_NOT_ALLOWED');
    }
  }
];
