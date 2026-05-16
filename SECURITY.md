# Security Policy

## Reporting a Vulnerability

If you discover a security issue in `shai-scan` itself or believe the bundled campaign database contains inaccurate or outdated information that could mislead users, please report it responsibly.

**Preferred channels:**

- Open a GitHub Issue on [digi4care/shai-scan](https://github.com/digi4care/shai-scan) and label it `security`
- Email the maintainer directly: **security@digi4care.com** (PGP key available on request)

Please include:

- A clear description of the issue
- Steps to reproduce (if applicable)
- The version of `shai-scan` you are using
- Any suggested remediation

## Response Timeline

| Severity | Acknowledgment | Target Fix |
|----------|---------------|------------|
| Critical | 48 hours | 7 days |
| High | 48 hours | 14 days |
| Medium/Low | 72 hours | 30 days |

## Scope

**In scope:**

- The `shai-scan` source code and CLI behavior
- The accuracy and completeness of the campaign database (`src/db.ts`)
- Build, release, and CI/CD pipeline integrity

**Out of scope:**

- Vulnerabilities in third-party packages detected by the scanner
- Security issues in upstream ecosystems (npm, PyPI, registries)
- End-user misconfiguration or misuse

## Supported Versions

Only the latest published version of `shai-scan` receives security updates. Users are strongly encouraged to always run the most recent release:

```bash
npx shai-scan@latest
```

## Disclosure Policy

We follow coordinated disclosure. Once a fix is released, we will publish a GitHub Security Advisory and a release note detailing the issue, affected versions, and mitigation steps.
