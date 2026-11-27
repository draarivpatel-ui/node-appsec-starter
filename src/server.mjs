import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadConfig } from './config.mjs';
import { createSecurityToolkit, SESSION_COOKIE } from './security.mjs';

export class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function finiteNumber(value) {
  return Number.isFinite(value) ? value : null;
}

function isPlainishObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function readBody(req, maxBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      throw new HttpError(413, 'ERR_BODY_TOO_LARGE', 'request body exceeded the configured limit');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function sendJson(res, toolkit, status, value, extraHeaders = {}) {
  const body = toolkit.json.stringify(value);
  res.statusCode = status;
  for (const [name, headerValue] of Object.entries(extraHeaders)) {
    res.setHeader(name, headerValue);
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', Buffer.byteLength(body));
  res.end(body);
}

function sendText(res, status, body, contentType, extraHeaders = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  res.statusCode = status;
  for (const [name, headerValue] of Object.entries(extraHeaders)) {
    res.setHeader(name, headerValue);
  }
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Length', bytes.length);
  res.end(bytes);
}

function errorStatus(error) {
  if (error instanceof HttpError) return error.status;
  if (Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599) return error.status;
  const code = String(error?.code || '');
  if (/SIGNATURE|TOKEN|COOKIE|SESSION|ORIGIN|CROSS_SITE|REPLAYED|JWT/.test(code)) return 403;
  return 400;
}

function publicCode(error) {
  const code = typeof error?.code === 'string' && /^[A-Z0-9_/-]{3,96}$/i.test(error.code)
    ? error.code
    : 'ERR_SECURITY_REJECTED';
  return code.replaceAll('/', '_');
}

function sendError(res, toolkit, error) {
  const status = errorStatus(error);
  const body = {
    ok: false,
    error: {
      code: publicCode(error),
      message: status >= 500 ? 'internal server error' : 'request rejected'
    }
  };
  if (error instanceof HttpError && error.details !== undefined) {
    body.error.details = error.details;
  }
  try {
    sendJson(res, toolkit, status, body);
  } catch (_) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end('{"ok":false,"error":{"code":"ERR_INTERNAL","message":"internal server error"}}');
  }
}

function requireJsonContent(req) {
  const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new HttpError(415, 'ERR_UNSUPPORTED_MEDIA_TYPE', 'application/json is required');
  }
}

async function readJsonBody(req, toolkit) {
  requireJsonContent(req);
  const raw = await readBody(req, toolkit.config.BODY_MAX_BYTES);
  if (raw.length === 0) {
    throw new HttpError(400, 'ERR_EMPTY_JSON_BODY', 'JSON request body is required');
  }
  const text = raw.toString('utf8');
  const value = toolkit.json.parse(text);
  if (!isPlainishObject(value)) {
    throw new HttpError(400, 'ERR_JSON_OBJECT_REQUIRED', 'top level JSON object is required');
  }
  return value;
}

function requireStringField(object, field, maxLength) {
  const value = object[field];
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new HttpError(400, 'ERR_INVALID_FIELD', `${field} must be a non-empty string within the configured length`);
  }
  return value;
}

function newSessionId() {
  return randomBytes(18).toString('base64url');
}

function sessionCookiePresent(req) {
  const header = req.headers.cookie;
  return typeof header === 'string' && header.includes(`${SESSION_COOKIE}=`);
}

function setSessionCookies(res, sessionCookie, csrfCookie) {
  res.setHeader('Set-Cookie', [sessionCookie, csrfCookie]);
}

async function establishOrRotateSession(req, res, toolkit, existingSession) {
  const sessionId = existingSession?.claims?.sub || newSessionId();
  if (existingSession) {
    await toolkit.csrf.verifyRequest(req, { sessionId });
  }
  const signedCookie = toolkit.signSessionCookie(sessionId);
  const sessionCookie = toolkit.serializeSessionCookie(signedCookie);
  const pair = toolkit.csrf.issueTokenPair({}, { sessionId });
  setSessionCookies(res, sessionCookie, pair.setCookie);
  sendJson(res, toolkit, existingSession ? 200 : 201, {
    ok: true,
    session: {
      authenticated: true,
      rotated: Boolean(existingSession),
      expiresInSeconds: toolkit.config.SESSION_TTL_SECONDS
    },
    csrf: {
      token: pair.token,
      expiresAt: new Date(pair.expiresAt).toISOString()
    }
  });
}

async function handleSession(req, res, toolkit) {
  if (req.method === 'GET') {
    const session = toolkit.verifySessionCookie(req.headers.cookie);
    const sessionId = session.claims.sub;
    const pair = toolkit.csrf.issueTokenPair({}, { sessionId });
    res.setHeader('Set-Cookie', pair.setCookie);
    sendJson(res, toolkit, 200, {
      ok: true,
      session: {
        authenticated: true,
        issuer: session.claims.iss,
        audience: session.claims.aud,
        issuedAt: new Date(session.claims.iat * 1000).toISOString(),
        expiresAt: new Date(session.claims.exp * 1000).toISOString(),
        keyRotated: session.verifiedCookie.rotated
      },
      csrf: {
        token: pair.token,
        expiresAt: new Date(pair.expiresAt).toISOString()
      }
    });
    return;
  }

  await readBody(req, toolkit.config.BODY_MAX_BYTES);
  if (!sessionCookiePresent(req)) {
    await establishOrRotateSession(req, res, toolkit, null);
    return;
  }

  const existingSession = toolkit.verifySessionCookie(req.headers.cookie);
  await establishOrRotateSession(req, res, toolkit, existingSession);
}

async function handleJson(req, res, toolkit) {
  const value = await readJsonBody(req, toolkit);
  const keys = Object.keys(value).sort();
  sendJson(res, toolkit, 200, {
    ok: true,
    json: {
      keys,
      keyCount: keys.length,
      depthSafe: true,
      prototypeSafe: true
    }
  });
}

async function handleFiles(req, res, toolkit, url) {
  const name = url.searchParams.get('name');
  if (!name) {
    throw new HttpError(400, 'ERR_FILE_NAME_REQUIRED', 'name query parameter is required');
  }
  const resolved = toolkit.files.resolve(name);
  const checked = toolkit.files.realpathCheck(resolved);
  let content;
  try {
    content = await readFile(checked, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') {
      throw new HttpError(404, 'ERR_FILE_NOT_FOUND', 'file was not found inside the sandbox');
    }
    throw error;
  }
  sendText(res, 200, content, 'text/plain; charset=utf-8', {
    'Content-Disposition': 'inline; filename="download.txt"'
  });
}

function handleRedirect(req, res, toolkit, url) {
  const next = url.searchParams.get('next') || '/';
  const target = toolkit.redirect.assert(next);
  res.statusCode = 302;
  res.setHeader('Location', target);
  res.setHeader('Content-Length', '0');
  res.end();
}

async function handleWebhook(req, res, toolkit) {
  const raw = await readBody(req, toolkit.config.BODY_MAX_BYTES);
  if (raw.length === 0) {
    throw new HttpError(400, 'ERR_WEBHOOK_BODY_REQUIRED', 'webhook body is required');
  }
  const verification = toolkit.webhook.verify('github', raw, req.headers);
  const payload = toolkit.json.parse(raw.toString('utf8'));
  if (!isPlainishObject(payload)) {
    throw new HttpError(400, 'ERR_JSON_OBJECT_REQUIRED', 'top level JSON object is required');
  }
  sendJson(res, toolkit, 200, {
    ok: true,
    webhook: {
      provider: verification.provider,
      valid: verification.valid,
      timestamp: verification.timestamp ? verification.timestamp.toISOString() : null,
      secretIndex: verification.secretIndex,
      replayKey: verification.replayKey
    }
  });
}

async function handleFetchPreview(req, res, toolkit) {
  const body = await readJsonBody(req, toolkit);
  const input = requireStringField(body, 'url', 2048);
  const result = toolkit.url.validate(input);
  if (!result.ok) {
    throw new HttpError(400, `ERR_URLGUARD_${result.code}`, 'URL failed SSRF policy validation', {
      guardCode: result.code
    });
  }
  sendJson(res, toolkit, 200, {
    ok: true,
    url: {
      normalized: result.normalized,
      hostname: result.hostname,
      port: result.port === undefined ? null : result.port,
      ipClass: result.ipClass,
      fetched: false
    }
  });
}

async function handleExportCsv(req, res, toolkit) {
  const body = await readJsonBody(req, toolkit);
  if (!Array.isArray(body.rows) || body.rows.length === 0) {
    throw new HttpError(400, 'ERR_CSV_ROWS_REQUIRED', 'rows must be a non-empty array');
  }
  const csv = toolkit.stringifyCsv(body.rows);
  sendText(res, 200, csv, 'text/csv; charset=utf-8', {
    'Content-Disposition': 'attachment; filename="export.csv"'
  });
}

function containsActiveHtml(input) {
  const lower = input.toLowerCase();
  return /<\s*(script|iframe|object|embed|svg|math)\b/.test(lower)
    || /\son[a-z0-9_-]+\s*=/.test(lower)
    || /(?:href|src|xlink:href)\s*=\s*['"]?\s*javascript:/.test(lower);
}

async function handleRenderBio(req, res, toolkit) {
  const body = await readJsonBody(req, toolkit);
  const input = requireStringField(body, 'html', 32768);
  const sanitized = toolkit.html.sanitize(input);
  if (containsActiveHtml(input)) {
    throw new HttpError(400, 'ERR_HTMLCLEAN_ACTIVE_CONTENT', 'active HTML content is rejected', {
      sanitizedLength: sanitized.length
    });
  }
  sendJson(res, toolkit, 200, {
    ok: true,
    html: sanitized,
    changed: sanitized !== input
  });
}

async function handleCheckRegex(req, res, toolkit) {
  const body = await readJsonBody(req, toolkit);
  const pattern = requireStringField(body, 'pattern', 1024);
  const flags = typeof body.flags === 'string' ? body.flags : '';
  if (flags.length > 16) {
    throw new HttpError(400, 'ERR_INVALID_FIELD', 'flags is too long');
  }
  let analysis;
  try {
    analysis = toolkit.assertRegex(pattern, flags);
  } catch (error) {
    if (error?.name === 'UnsafeRegexError') {
      throw new HttpError(400, 'ERR_REGEX_REDOS_RISK', 'regular expression failed the ReDoS policy', {
        risk: error.risk,
        findings: error.findings.slice(0, 5).map((finding) => ({
          rule: finding.rule,
          severity: finding.severity,
          complexity: finding.complexity,
          cwe: finding.cwe
        }))
      });
    }
    throw error;
  }
  sendJson(res, toolkit, 200, {
    ok: true,
    regex: {
      safe: analysis.safe,
      risk: analysis.risk,
      score: analysis.score,
      worstCase: analysis.complexity.worstCase,
      captureCount: analysis.parsed.captureCount
    }
  });
}

async function handleInspectZip(req, res, toolkit) {
  const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/zip' && contentType !== 'application/octet-stream') {
    throw new HttpError(415, 'ERR_UNSUPPORTED_MEDIA_TYPE', 'application/zip is required');
  }
  const raw = await readBody(req, toolkit.config.ZIP_MAX_BYTES);
  if (raw.length === 0) {
    throw new HttpError(400, 'ERR_ZIP_BODY_REQUIRED', 'ZIP bytes are required');
  }
  const report = toolkit.inspectZip(raw);
  sendJson(res, toolkit, 200, {
    ok: true,
    zip: {
      safe: report.safe,
      entries: report.entries.map((entry) => ({
        name: entry.name,
        directory: entry.directory,
        compressedSize: entry.compressedSize,
        uncompressedSize: entry.uncompressedSize,
        compressionRatio: finiteNumber(entry.compressionRatio)
      })),
      totals: {
        entries: report.totals.entries,
        files: report.totals.files,
        directories: report.totals.directories,
        compressedBytes: report.totals.compressedBytes,
        uncompressedBytes: report.totals.uncompressedBytes,
        archiveBytes: report.totals.archiveBytes,
        compressionRatio: finiteNumber(report.totals.compressionRatio),
        maximumEntryCompressionRatio: finiteNumber(report.totals.maximumEntryCompressionRatio)
      }
    }
  });
}

async function handleScanSnippet(req, res, toolkit) {
  const body = await readJsonBody(req, toolkit);
  const text = requireStringField(body, 'text', 65536);
  const findings = toolkit.scanSecrets(text).map((finding) => ({
    detector: finding.detector,
    provider: finding.provider,
    name: finding.name,
    severity: finding.severity,
    line: finding.line,
    column: finding.column,
    redacted: finding.redacted,
    fingerprint: finding.fingerprint
  }));
  if (findings.length > 0) {
    throw new HttpError(400, 'ERR_SECRETSCAN_FINDINGS', 'potential secret material detected', { findings });
  }
  sendJson(res, toolkit, 200, {
    ok: true,
    secrets: {
      findings: 0,
      clean: true
    }
  });
}

async function routeRequest(req, res, toolkit) {
  const url = new URL(req.url || '/', 'http://127.0.0.1');
  const pathname = url.pathname;

  if (pathname === '/health' && req.method === 'GET') {
    sendJson(res, toolkit, 200, { ok: true, service: 'node-appsec-starter' });
    return;
  }
  if (pathname === '/api/json' && req.method === 'POST') return handleJson(req, res, toolkit);
  if (pathname === '/api/files' && req.method === 'GET') return handleFiles(req, res, toolkit, url);
  if (pathname === '/api/redirect' && req.method === 'GET') return handleRedirect(req, res, toolkit, url);
  if (pathname === '/api/session' && (req.method === 'POST' || req.method === 'GET')) return handleSession(req, res, toolkit);
  if (pathname === '/api/webhook' && req.method === 'POST') return handleWebhook(req, res, toolkit);
  if (pathname === '/api/fetch-preview' && req.method === 'POST') return handleFetchPreview(req, res, toolkit);
  if (pathname === '/api/export-csv' && req.method === 'POST') return handleExportCsv(req, res, toolkit);
  if (pathname === '/api/render-bio' && req.method === 'POST') return handleRenderBio(req, res, toolkit);
  if (pathname === '/api/check-regex' && req.method === 'POST') return handleCheckRegex(req, res, toolkit);
  if (pathname === '/api/inspect-zip' && req.method === 'POST') return handleInspectZip(req, res, toolkit);
  if (pathname === '/api/scan-snippet' && req.method === 'POST') return handleScanSnippet(req, res, toolkit);

  const knownPath = pathname === '/api/json'
    || pathname === '/api/files'
    || pathname === '/api/redirect'
    || pathname === '/api/session'
    || pathname === '/api/webhook'
    || pathname === '/api/fetch-preview'
    || pathname === '/api/export-csv'
    || pathname === '/api/render-bio'
    || pathname === '/api/check-regex'
    || pathname === '/api/inspect-zip'
    || pathname === '/api/scan-snippet';
  if (knownPath) {
    throw new HttpError(405, 'ERR_METHOD_NOT_ALLOWED', 'method is not allowed for this endpoint');
  }
  throw new HttpError(404, 'ERR_NOT_FOUND', 'route was not found');
}

export function createApp(options = {}) {
  const config = options.config || loadConfig(options.env || process.env, options.configOptions);
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const defaultFixtureRoot = path.resolve(moduleDirectory, '../fixtures/files');
  const toolkit = createSecurityToolkit(config, {
    fixtureRoot: options.fixtureRoot || defaultFixtureRoot,
    logWriter: options.logWriter
  });

  const server = http.createServer((req, res) => {
    const started = process.hrtime.bigint();
    res.on('finish', () => {
      try {
        const durationMs = Number(process.hrtime.bigint() - started) / 1000000;
        const line = toolkit.log.json('info', 'http request', {
          method: req.method,
          path: new URL(req.url || '/', 'http://127.0.0.1').pathname,
          status: res.statusCode,
          durationMs: Math.round(durationMs * 10) / 10,
          remoteAddress: req.socket.remoteAddress,
          headers: {
            authorization: req.headers.authorization || null,
            cookie: req.headers.cookie || null,
            origin: req.headers.origin || null,
            userAgent: req.headers['user-agent'] || null
          }
        });
        toolkit.logWriter(line);
      } catch (_) {
      }
    });

    toolkit.applySecurityHeaders(res);
    toolkit.cors(req, res, () => {
      routeRequest(req, res, toolkit).catch((error) => {
        if (!res.headersSent) {
          sendError(res, toolkit, error);
          return;
        }
        res.end();
      });
    });
  });

  return {
    server,
    config,
    security: toolkit,
    listen(host = config.HOST, port = config.PORT) {
      return new Promise((resolve, reject) => {
        const onError = (error) => reject(error);
        server.once('error', onError);
        server.listen(port, host, () => {
          server.off('error', onError);
          resolve({ server, config, security: toolkit, address: server.address() });
        });
      });
    },
    close() {
      return new Promise((resolve, reject) => {
        if (!server.listening) {
          resolve();
          return;
        }
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  };
}

export async function startServer(options = {}) {
  const app = createApp(options);
  return app.listen();
}

const invokedAsMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (invokedAsMain) {
  const app = createApp();
  app.listen().then(({ address }) => {
    const line = app.security.log.json('info', 'server listening', {
      host: typeof address === 'object' && address ? address.address : null,
      port: typeof address === 'object' && address ? address.port : null,
      generatedSecrets: app.config.generatedSecrets
    });
    app.security.logWriter(line);
  }).catch((error) => {
    const line = app.security.log.json('error', 'server failed to start', {
      code: error?.code || 'ERR_STARTUP'
    });
    app.security.logWriter(line);
    process.exitCode = 1;
  });
}
