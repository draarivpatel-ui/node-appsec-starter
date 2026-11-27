# Contributing

Thanks for helping improve this AppSec reference starter.

## Ground rules

- Keep the project dependency free outside the 18 packages already listed in `package.json`.
- Do not add a runtime framework. The point of the starter is visible composition on the Node.js `http` module.
- Do not commit secrets, tokens, cookies, private keys, real webhook payloads, or personal data.
- Keep `package-lock.json` committed and `node_modules/` untracked.
- Add both benign and malicious regression tests for every security behavior change.
- Keep tests deterministic and offline. Tests must not call external network services.

## Local verification

```bash
npm ci
npm test
npx sentinel-lint scan src --json --quiet --fail-on error
```

The test runner explicitly enumerates test files in `scripts/run-tests.mjs` so it behaves the same on Linux, macOS, and Windows.

## Pull requests

- Keep one concern per pull request.
- Explain which attack class is affected and cite the CWE or OWASP category where useful.
- Update the README package mapping when an endpoint or security boundary changes.
- Confirm that CI is green on Node.js 20, 22, and 24 across Linux and Windows.
