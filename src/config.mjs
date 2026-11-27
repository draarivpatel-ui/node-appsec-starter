import { randomBytes } from 'node:crypto';
import { defineEnv, safeSnapshot, t } from 'envcage';

const SECRET_KEYS = ['SESSION_SECRET', 'CSRF_SECRET', 'WEBHOOK_SECRET', 'JWT_SECRET'];

function secretBytes() {
  return randomBytes(32).toString('base64url');
}

export function prepareEnv(source = process.env, { generateDevelopmentSecrets = true } = {}) {
  const merged = { ...source };
  const generated = [];
  const nodeEnv = String(merged.NODE_ENV || 'development').toLowerCase();
  if (generateDevelopmentSecrets && nodeEnv !== 'production') {
    for (const key of SECRET_KEYS) {
      if (merged[key] === undefined || merged[key] === '') {
        merged[key] = secretBytes();
        generated.push(key);
      }
    }
  }
  return { env: merged, generated };
}

export function loadConfig(source = process.env, options = {}) {
  const prepared = prepareEnv(source, options);
  const config = defineEnv({
    NODE_ENV: t.enum(['development', 'test', 'production']).default('development'),
    HOST: t.str({ minLength: 1, maxLength: 255, trim: true }).default('127.0.0.1'),
    PORT: t.port().default('8080'),
    SESSION_SECRET: t.secret({ minLength: 32, maxLength: 512 }),
    CSRF_SECRET: t.secret({ minLength: 32, maxLength: 512 }),
    WEBHOOK_SECRET: t.secret({ minLength: 32, maxLength: 512 }),
    JWT_SECRET: t.secret({ minLength: 32, maxLength: 512 }),
    ALLOWED_ORIGINS: t.csv({ unique: true, minItems: 1, maxItems: 32, trim: true }).default('http://127.0.0.1:8080,http://localhost:8080'),
    REDIRECT_ALLOWED_ORIGINS: t.csv({ unique: true, minItems: 1, maxItems: 32, trim: true }).default('http://127.0.0.1:8080,http://localhost:8080'),
    BODY_MAX_BYTES: t.int({ min: 1024, max: 1048576 }).default('65536'),
    ZIP_MAX_BYTES: t.int({ min: 1024, max: 10485760 }).default('1048576'),
    JSON_MAX_BYTES: t.int({ min: 1024, max: 1048576 }).default('65536'),
    SESSION_TTL_SECONDS: t.int({ min: 60, max: 86400 }).default('3600')
  }, prepared.env);

  return Object.freeze({
    ...config,
    generatedSecrets: Object.freeze(prepared.generated),
    snapshot: safeSnapshot(config)
  });
}
