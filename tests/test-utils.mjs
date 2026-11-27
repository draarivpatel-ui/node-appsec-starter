import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';

export { assert };

export function makeTestEnv() {
  return {
    NODE_ENV: 'test',
    HOST: '127.0.0.1',
    PORT: '8080',
    SESSION_SECRET: randomBytes(32).toString('base64url'),
    CSRF_SECRET: randomBytes(32).toString('base64url'),
    WEBHOOK_SECRET: randomBytes(32).toString('base64url'),
    JWT_SECRET: randomBytes(32).toString('base64url'),
    ALLOWED_ORIGINS: 'http://127.0.0.1:8080,http://localhost:8080',
    REDIRECT_ALLOWED_ORIGINS: 'http://127.0.0.1:8080,http://localhost:8080',
    BODY_MAX_BYTES: '65536',
    ZIP_MAX_BYTES: '1048576',
    JSON_MAX_BYTES: '65536',
    SESSION_TTL_SECONDS: '3600'
  };
}

export async function fetchText(baseUrl, requestPath, options = {}) {
  const response = await fetch(new URL(requestPath, baseUrl), options);
  const text = await response.text();
  return { response, text };
}

export async function fetchJson(baseUrl, requestPath, options = {}) {
  const { response, text } = await fetchText(baseUrl, requestPath, options);
  let body = null;
  try {
    body = text.length > 0 ? JSON.parse(text) : null;
  } catch (_) {
    body = null;
  }
  return { response, text, body };
}

export async function postJson(baseUrl, requestPath, payload, headers = {}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return fetchJson(baseUrl, requestPath, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...headers
    },
    body
  });
}

export function getSetCookies(response) {
  if (typeof response.headers.getSetCookie === 'function') {
    return response.headers.getSetCookie();
  }
  const combined = response.headers.get('set-cookie');
  return combined ? [combined] : [];
}

export function updateCookieJar(jar, setCookies) {
  for (const header of setCookies) {
    const first = header.split(';', 1)[0];
    const equals = first.indexOf('=');
    if (equals > 0) {
      jar.set(first.slice(0, equals), first.slice(equals + 1));
    }
  }
  return jar;
}

export function cookieHeader(jar) {
  return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

export function githubSignature(body, secret) {
  return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
}

export function attackJson(body) {
  return body?.error?.code || null;
}
