# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes apply to the current `main` branch and the newest 1.x state. Users should upgrade to the fixed state as soon as it is available. This repository is a learning and integration template, not a hosted service. Review and adapt every control before using it in production.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/node-appsec-starter/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected endpoint or package boundary.
- A minimal reproduction, the expected behavior and the observed behavior.
- The Node.js version and operating system.
- Your assessment of impact and a suggested fix if you have one.

Do not include real credentials, tokens, cookies, private keys, customer data or personal data in a report. Redact secrets before attaching logs.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

## Scope

Reports are welcome for:

- Incorrect composition of a security library in `src/`.
- Missing or unsafe response headers.
- Authentication, CSRF, webhook, SSRF, path, redirect, archive, CSV, HTML, regex, JSON or secret scanning bypasses in the reference server.
- CI or test cases that falsely claim protection.

The individual libraries have their own upstream repositories. If a defect is clearly inside one library rather than in this starter's composition, report it in that library's repository.
