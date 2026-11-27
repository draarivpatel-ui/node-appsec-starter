# Security policy

## Supported versions

The `main` branch is the supported line for this reference starter. It is a learning and integration template, not a hosted service. Review and adapt every control before using it in production.

## Reporting a vulnerability

Please do not open a public issue with reproduction steps for a vulnerability. Use the repository's GitHub Security Advisories page to report the issue privately. Include the affected endpoint or package boundary, a minimal reproduction, the expected behavior, and the observed behavior.

Do not include real credentials, tokens, cookies, private keys, or personal data in a report. Redact secrets before attaching logs.

## Scope

This repository demonstrates defensive use of the 18 package security suite. Reports are welcome for:

- incorrect composition of a security library in `src/`
- missing or unsafe response headers
- authentication, CSRF, webhook, SSRF, path, redirect, archive, CSV, HTML, regex, JSON, or secret scanning bypasses in the reference server
- CI or test cases that falsely claim protection

The individual libraries have their own upstream repositories. If a defect is clearly inside one library rather than in this starter's composition, report it in that library's repository.
