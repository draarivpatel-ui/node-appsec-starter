# node-appsec-starter

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/draarivpatel-ui/node-appsec-starter/badge)](https://securityscorecards.dev/viewer/?uri=github.com/draarivpatel-ui/node-appsec-starter)

A runnable Node.js AppSec reference API and executable OWASP attack reproduction suite. It composes 18 zero dependency security libraries from npm into one hardened `node:http` server, then proves both the benign path and the attack path with real HTTP requests.

## Quickstart

Requires Node.js 20 or newer.

```bash
git clone https://github.com/draarivpatel-ui/node-appsec-starter.git
cd node-appsec-starter
npm ci
npm test
```

Verified local suite: **64 tests**. The tests start the real server on an ephemeral loopback port, fire real `fetch()` requests, build real ZIP archives in memory, sign real webhook payloads, scan real fixture files, and verify the installed supply chain. They do not call external network services.

Run the API locally:

```bash
npm start
```

In development and test modes, missing secrets are generated with `crypto.randomBytes` so the server fails closed in production but remains easy to inspect locally. Generated secrets are ephemeral. For a real deployment, set strong random values for every variable shown in `.env.example`.

## Supply chain proof

`npm ci` installs exactly **18 packages** and no transitive third-party packages:

- 17 runtime security libraries
- `sentinel-lint` as the only development dependency

The test suite verifies all three layers:

1. `package.json` contains only the expected dependencies.
2. `package-lock.json` contains exactly 18 `node_modules/` package entries.
3. Every installed `node_modules/<package>/package.json` has an empty or absent `dependencies` object.

`node_modules/` is intentionally not committed. `package-lock.json` is committed so `npm ci` reproduces the same tree in CI.

## Architecture

```text
                         ┌──────────────────────────────────────────┐
                         │            node:http server              │
                         └──────────────────────────────────────────┘
                                           │
              ┌────────────────────────────┼────────────────────────────┐
              │                            │                            │
        envcage config              headersafe headers             corscage policy
        secret redaction            CSP, HSTS, nosniff             allowlist + preflight
              │                            │                            │
              └────────────────────────────┼────────────────────────────┘
                                           │
                                    logcage NDJSON
                                    CWE-117 safe logs
                                           │
        ┌──────────────────────────────────┼──────────────────────────────────┐
        │                                  │                                  │
   request parsers                    identity flows                    content defenses
   jsoncage                           cookiecage                        htmlclean
   zipcage                            csrfshield                        csvshield
   pathcage                           jwtguard                          regex-shield
   redirectcage                       hookverify                        secretsweep
                                      urlguard
                                           │
                             sentinel-lint in development CI
```

## Package and attack map

| Package | Main CWE or OWASP class | Runtime proof |
| --- | --- | --- |
| `envcage` | CWE-20 improper input validation, CWE-798 hardcoded credential risk | Validates environment shape at boot and redacts every `SecretString` in snapshots and logs |
| `headersafe` | OWASP A05 security misconfiguration, CWE-693 protection mechanism failure | Applies CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP, and frame denial |
| `corscage` | CWE-346 origin validation error, CWE-942 permissive cross-domain policy | Uses a strict origin allowlist, authoritative `Vary: Origin`, and hardened preflight rejection |
| `logcage` | CWE-117 log injection, CWE-532 sensitive data exposure | Emits single-line NDJSON and redacts Bearer tokens, cookies, and configured secrets |
| `jsoncage` | CWE-20 improper input validation, CWE-915 mass assignment and prototype pollution | `POST /api/json` rejects `__proto__`, duplicate keys, unsafe numbers, and depth bombs |
| `pathcage` | CWE-22 path traversal | `GET /api/files` keeps resolution inside the fixture sandbox and rejects NULs, encoded traversal, absolute paths, and symlink escapes |
| `redirectcage` | CWE-601 open redirect | `GET /api/redirect` rejects protocol-relative URLs, `javascript:`, CRLF, dot segments, and non-allowlisted hosts |
| `cookiecage` | CWE-614 sensitive cookie without Secure, CWE-565 unsigned cookie | `POST /api/session` signs the session cookie and enforces `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/` |
| `@aarivbuildz/csrfshield` | CWE-352 cross-site request forgery | Session rotation requires the double-submit `x-csrf-token` plus matching signed cookie and rejects foreign origins |
| `@aarivbuildz/jwtguard` | CWE-347 improper verification of cryptographic signature | Session claims are signed and verified with explicit HS256 algorithm, issuer, audience, expiration, and required claims |
| `@aarivbuildz/hookverify` | CWE-345 insufficient verification of data authenticity, CWE-294 replay attack | `POST /api/webhook` verifies GitHub-style HMAC signatures and rejects replayed deliveries |
| `@aarivbuildz/urlguard` | CWE-918 server-side request forgery | `POST /api/fetch-preview` validates outbound URLs without fetching them and blocks metadata, loopback, private CIDRs, userinfo, and unsafe schemes |
| `@aarivbuildz/csvshield` | CWE-1236 CSV formula injection | `POST /api/export-csv` serializes safe rows and rejects formula-trigger cells |
| `@aarivbuildz/htmlclean` | CWE-79 cross-site scripting | `POST /api/render-bio` sanitizes allowed prose markup and strict mode rejects active HTML, event handlers, and `javascript:` URLs |
| `@aarivbuildz/regex-shield` | CWE-1333 inefficient regular expression complexity | `POST /api/check-regex` rejects nested quantifiers and overlapping alternation before user regexes can run |
| `zipcage` | CWE-22 zip slip, CWE-409 zip bomb | `POST /api/inspect-zip` inspects real ZIP bytes and rejects traversal paths and excessive compression ratios |
| `@aarivbuildz/secretsweep` | CWE-798 exposed secret | `POST /api/scan-snippet` blocks likely secret material and returns only redacted findings and fingerprints |
| `sentinel-lint` | CI evidence for the vulnerability classes above | Development-only static scanner. Tests prove it catches a vulnerable fixture, emits SARIF 2.1.0, and reports zero error or critical findings in `src/` |

## API endpoints

| Endpoint | Benign behavior | Attack reproduction |
| --- | --- | --- |
| `GET /health` | Returns service health with hardened headers | Headers and CORS behavior are asserted directly |
| `POST /api/json` | Parses strict JSON and returns key metadata | `400` for prototype keys, duplicates, and depth bombs |
| `GET /api/files?name=hello.txt` | Reads a sandboxed fixture file | `400` for traversal, NUL, absolute paths, encoded layers, and symlink escapes; `404` inside sandbox misses |
| `GET /api/redirect?next=/settings` | Emits a `302` to a safe target | `400` for open redirect, scheme, CRLF, host, and dot-segment attacks |
| `POST /api/session` | Creates or rotates a signed session and CSRF token pair | `403` for invalid signed cookies, missing CSRF tokens, or foreign origins |
| `GET /api/session` | Verifies signed cookie and JWT claims | `403` for missing or tampered cookies |
| `POST /api/webhook` | Verifies raw-body GitHub-style HMAC signatures | `403` for signature mismatch and replay |
| `POST /api/fetch-preview` | Validates and normalizes a public HTTPS URL without fetching | `400` for SSRF targets and unsafe schemes |
| `POST /api/export-csv` | Emits safe CSV | `400` for formula injection |
| `POST /api/render-bio` | Returns sanitized inert markup | `400` for active HTML, event handlers, and script URLs |
| `POST /api/check-regex` | Returns regex risk metadata | `400` for ReDoS shapes |
| `POST /api/inspect-zip` | Returns a bounded ZIP inspection report | `400` for zip slip and compression bombs |
| `POST /api/scan-snippet` | Returns a clean scan result | `400` with redacted findings when secret-shaped material appears |

## Webhook example

The verifier uses the exact raw bytes received over HTTP. Do not parse and reserialize before verification.

```js
const signature = createHmac('sha256', process.env.WEBHOOK_SECRET)
  .update(rawBody)
  .digest('hex');
// send as x-hub-signature-256: sha256=<hex>
```

The integration tests generate real HMAC signatures at runtime. No real secret is stored in the repository.

## CI

GitHub Actions runs the full matrix on every push and pull request:

- Node.js 20, 22, and 24
- Ubuntu 24.04 and Windows latest
- `npm ci`
- `npm test`
- `npx sentinel-lint scan src --json --quiet --fail-on error`

The matrix is 6 jobs. The test suite itself also runs `sentinel-lint` against the intentionally vulnerable fixture in `fixtures/vulnerable-sample/` and validates the SARIF structure.

## Security posture and limits

This is a reference starter, not a complete production application. It intentionally avoids frameworks so every control is visible. Before production use, review cookie secure transport assumptions, deployment-specific CORS origins, secret management, rate limiting, account lifecycle, logging sinks, HTTPS termination, and incident response. See `SECURITY.md` for vulnerability reporting.
