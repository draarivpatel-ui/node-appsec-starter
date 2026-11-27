import { createCage } from 'pathcage';
import { applySecurityHeaders } from 'headersafe';
import { createRedirectGuard } from 'redirectcage';
import {
  createCookieJarGuard,
  parseCookieHeader,
  serializeCookie,
  signCookieValue,
  verifyCookieValue
} from 'cookiecage';
import { assertSafeZipBuffer } from 'zipcage';
import { createLogCage } from 'logcage';
import { createNodeCorsMiddleware } from 'corscage';
import { createJsonCage } from 'jsoncage';
import { createVerifier, MemoryReplayStore } from '@aarivbuildz/hookverify';
import { signJwt, verifyJwt } from '@aarivbuildz/jwtguard';
import { createShield, nodeCrypto } from '@aarivbuildz/csrfshield/node';
import { createGuard } from '@aarivbuildz/urlguard';
import { stringifySafeCsv } from '@aarivbuildz/csvshield';
import { createSanitizer, PROSE_POLICY } from '@aarivbuildz/htmlclean';
import { assertSafeRegex } from '@aarivbuildz/regex-shield';
import { scanText } from '@aarivbuildz/secretsweep';

export const SESSION_COOKIE = '__Host-session';
export const CSRF_COOKIE = '__Host-csrf';
export const JWT_ISSUER = 'node-appsec-starter';
export const JWT_AUDIENCE = 'session';

export function createSecurityToolkit(config, { fixtureRoot, logWriter } = {}) {
  const sessionSecret = config.SESSION_SECRET.reveal();
  const csrfSecret = config.CSRF_SECRET.reveal();
  const webhookSecret = config.WEBHOOK_SECRET.reveal();
  const jwtSecret = config.JWT_SECRET.reveal();
  const secrets = Object.freeze([sessionSecret, csrfSecret, webhookSecret, jwtSecret]);

  const keyring = Object.freeze({
    keys: Object.freeze([Object.freeze({ id: 'v1', secret: sessionSecret })])
  });

  const files = createCage(fixtureRoot, {
    noSymlinks: true,
    mustExist: true,
    decodeCheck: true,
    maxPathLength: 512
  });

  const redirect = createRedirectGuard({
    allowedOrigins: config.REDIRECT_ALLOWED_ORIGINS,
    allowIpLiterals: true,
    allowQuery: true,
    allowHash: false,
    normalizeDotSegments: false,
    fallback: '/',
    throwOnUnsafe: true,
    maxLength: 1024
  });

  const cors = createNodeCorsMiddleware({
    allowedOrigins: config.ALLOWED_ORIGINS,
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['content-type', 'x-csrf-token'],
    exposeHeaders: [],
    maxAge: 600,
    rejectDisallowedPreflight: true
  });

  const json = createJsonCage({
    maxBytes: config.JSON_MAX_BYTES,
    maxDepth: 16,
    maxKeys: 200,
    maxArrayLength: 1000,
    maxNodes: 5000,
    duplicateKeys: 'reject',
    protoPolicy: 'reject',
    nullPrototype: true,
    rejectUnsafeIntegers: true
  });

  const cookies = createCookieJarGuard({
    keyOrKeyring: keyring,
    serialize: {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Strict'
    },
    parse: {
      duplicatePolicy: 'reject',
      strictPercentEncoding: true
    }
  });

  const csrf = createShield({
    secrets: [csrfSecret],
    crypto: nodeCrypto,
    origin: config.ALLOWED_ORIGINS,
    cookie: {
      name: CSRF_COOKIE,
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict'
    },
    header: 'x-csrf-token',
    tokenTtlMs: Math.min(config.SESSION_TTL_SECONDS * 1000, 3600000)
  });

  const webhookReplayStore = new MemoryReplayStore({ maxEntries: 1000, ttlSeconds: 600 });
  const webhook = createVerifier({
    secret: webhookSecret,
    replayStore: webhookReplayStore,
    toleranceSeconds: 300
  });

  const url = createGuard({
    allowedSchemes: ['https:'],
    allowUserinfo: false,
    allowedPorts: 'default-only',
    hostPolicy: {},
    dns: false,
    checkRebinding: false,
    idna: 'ascii-only',
    maxInputLength: 2048
  });

  const log = createLogCage({
    extraSecrets: secrets,
    maxLength: 2048,
    maxOutputBytes: 16384,
    pii: { email: true, luhnCard: true, ssn: true, ipv4: false }
  });

  const html = createSanitizer(PROSE_POLICY);

  return Object.freeze({
    config,
    files,
    redirect,
    cors,
    json,
    cookies,
    csrf,
    webhook,
    url,
    log,
    html,
    keyring,
    secrets,
    logWriter: logWriter || ((line) => process.stdout.write(`${line}\n`)),
    applySecurityHeaders(response) {
      return applySecurityHeaders(response, {
        hsts: { maxAge: 31536000, includeSubDomains: true },
        crossOriginResourcePolicy: 'same-origin',
        csp: { preset: 'strict' }
      });
    },
    signSessionJwt(sessionId) {
      return signJwt({
        sub: sessionId,
        iss: JWT_ISSUER,
        aud: JWT_AUDIENCE
      }, jwtSecret, {
        algorithm: 'HS256',
        expiresInSeconds: config.SESSION_TTL_SECONDS
      });
    },
    verifySessionJwt(token) {
      return verifyJwt(token, jwtSecret, {
        algorithms: ['HS256'],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        requiredClaims: ['exp', 'iat', 'sub']
      });
    },
    signSessionCookie(sessionId) {
      const jwt = this.signSessionJwt(sessionId);
      return signCookieValue(SESSION_COOKIE, jwt, keyring, {
        maxAge: config.SESSION_TTL_SECONDS
      });
    },
    serializeSessionCookie(signedValue) {
      return serializeCookie(SESSION_COOKIE, signedValue, {
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        maxAge: config.SESSION_TTL_SECONDS
      });
    },
    verifySessionCookie(cookieHeader) {
      if (typeof cookieHeader !== 'string' || cookieHeader.trim() === '') {
        const error = new Error('session cookie is missing');
        error.code = 'ERR_SESSION_COOKIE_MISSING';
        throw error;
      }
      const parsed = parseCookieHeader(cookieHeader, {
        duplicatePolicy: 'reject',
        strictPercentEncoding: true
      });
      const signed = parsed[SESSION_COOKIE];
      if (!signed) {
        const error = new Error('session cookie is missing');
        error.code = 'ERR_SESSION_COOKIE_MISSING';
        throw error;
      }
      const verified = verifyCookieValue(SESSION_COOKIE, signed, keyring);
      const claims = this.verifySessionJwt(verified.value);
      return Object.freeze({ claims, verifiedCookie: verified, cookies: parsed });
    },
    inspectZip(bytes) {
      return assertSafeZipBuffer(bytes, {
        maxArchiveBytes: config.ZIP_MAX_BYTES,
        maxEntries: 100,
        maxEntryUncompressedBytes: 1024 * 1024,
        maxTotalUncompressedBytes: 4 * 1024 * 1024,
        maxCompressionRatio: 100
      });
    },
    stringifyCsv(rows) {
      return stringifySafeCsv(rows, {
        mode: 'reject',
        eol: '\n',
        trailingEol: true,
        maxRows: 500,
        maxColumns: 50,
        maxCellBytes: 4096,
        maxTotalBytes: config.BODY_MAX_BYTES
      });
    },
    assertRegex(pattern, flags) {
      return assertSafeRegex({ pattern, flags }, { threshold: 'medium', witnesses: true });
    },
    scanSecrets(text) {
      return scanText(text, { minSeverity: 'low', allowPlaceholder: false });
    }
  });
}
