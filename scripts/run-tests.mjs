import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const TEST_FILES = Object.freeze([
  'tests/config-and-supply-chain.test.mjs',
  'tests/security-e2e.test.mjs',
  'tests/sentinel.test.mjs'
]);

const DEFAULT_TIMEOUT_MS = 15000;

async function runOne(test, context, timeoutMs) {
  let timer;
  try {
    await Promise.race([
      test.run(context),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`test timed out after ${timeoutMs} ms`)), timeoutMs);
      })
    ]);
    return { ok: true };
  } catch (error) {
    return { ok: false, error };
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const timeoutMs = Number.parseInt(process.env.APPSEC_TEST_TIMEOUT_MS || String(DEFAULT_TIMEOUT_MS), 10);
  let total = 0;
  let passed = 0;
  let failed = 0;

  for (const relativeFile of TEST_FILES) {
    const absoluteFile = path.join(root, relativeFile);
    let module;
    try {
      module = await import(pathToFileURL(absoluteFile).href);
    } catch (error) {
      total += 1;
      failed += 1;
      console.error(`[fail] ${relativeFile} :: module import`);
      console.error(error?.stack || error);
      continue;
    }

    const context = { root, file: relativeFile };
    let setupError = null;
    if (typeof module.setup === 'function') {
      try {
        await module.setup(context);
      } catch (error) {
        setupError = error;
      }
    }

    if (setupError) {
      total += 1;
      failed += 1;
      console.error(`[fail] ${relativeFile} :: setup`);
      console.error(setupError?.stack || setupError);
    } else {
      for (const test of module.tests || []) {
        total += 1;
        const result = await runOne(test, context, timeoutMs);
        if (result.ok) {
          passed += 1;
          console.log(`[pass] ${relativeFile} :: ${test.name}`);
        } else {
          failed += 1;
          console.error(`[fail] ${relativeFile} :: ${test.name}`);
          console.error(result.error?.stack || result.error);
        }
      }
    }

    if (typeof module.teardown === 'function') {
      try {
        await module.teardown(context);
      } catch (error) {
        total += 1;
        failed += 1;
        console.error(`[fail] ${relativeFile} :: teardown`);
        console.error(error?.stack || error);
      }
    }
  }

  console.log(`test count: ${passed} passed, ${failed} failed, ${total} total`);
  if (failed > 0) process.exitCode = 1;
}

await main();
