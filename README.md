# shai-scan

> Zero-dependency CLI scanner for npm and PyPI supply chain compromises.

[![npm version](https://img.shields.io/npm/v/@digi4care/shai-scan)](https://www.npmjs.com/package/@digi4care/shai-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-brightgreen)](https://nodejs.org/)

## Why?

On May 11, 2026, a self-propagating supply chain worm dubbed **Mini Shai-Hulud** (CVE-2026-45321, GHSA-g7cv-rxg3-hmpx) compromised the npm ecosystem. Attributed to **TeamPCP** (aka DeadCatx3, PCPcat, ShellForce, CipherForce), the malware hijacked GitHub Actions OIDC tokens to publish malicious packages with valid SLSA Build Level 3 provenance. It stole credentials from CI/CD pipelines, cloud providers, and cryptocurrency wallets, and installed persistence hooks in Claude Code and VS Code. A built-in dead-man switch threatened to wipe the user's home directory if npm tokens were revoked.

Affected packages included TanStack router and start packages, Mistral AI SDKs, OpenSearch client, UiPath tooling, and dozens of others. Because supply chain attacks move fast, organizations need a lightweight, trustworthy scanner they can run anywhere without adding new dependencies to their own attack surface.

## Features

- **Lockfile scanning** — Detects compromised npm and PyPI packages in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`, `poetry.lock`, `Pipfile.lock`, and `requirements.txt`
- **System IOC checks** — Scans running processes, filesystem artifacts, network connections, and known persistence paths for indicators of compromise
- **Zero runtime dependencies** — Uses only Node.js/Bun built-ins (`fs`, `path`, `child_process`, `os`). The scanner does not increase your supply chain risk
- **Multiple output formats** — Human-readable text, machine-readable JSON, and SARIF for GitHub Code Scanning
- **CI/CD native** — Exit codes designed for automation (`0` = clean, `1` = findings, `2` = error)
- **Path-agnostic** — Accept any directory; defaults to the current working directory
- **Campaign-based database** — New attack waves are added as discrete campaigns in `src/db.ts`; update the file and rerun

## Install

No installation required. Run directly with your package runner of choice:

```bash
# npx
npx @digi4care/shai-scan

# bunx
bunx @digi4care/shai-scan

# pnpm dlx
pnpm dlx @digi4care/shai-scan
```

Global install (optional):

```bash
npm install -g @digi4care/shai-scan
# or
pnpm add -g @digi4care/shai-scan
```

From source:

```bash
git clone https://github.com/digi4care/shai-scan.git
cd shai-scan
pnpm install
node src/cli.ts --help        # Node.js ≥ 22 (v24+ runs .ts natively)
# or
bun run src/cli.ts --help
```

## Usage

### Scan the current project

```bash
npx @digi4care/shai-scan
```

### Scan a specific path

```bash
npx @digi4care/shai-scan ~/projects/my-app
```

### JSON output for automation

```bash
npx @digi4care/shai-scan --json .
```

### SARIF output for GitHub Code Scanning

```bash
npx @digi4care/shai-scan --sarif --sarif-file results.sarif .
```

### CI/CD exit codes

```bash
#!/bin/bash
npx @digi4care/shai-scan --severity high . || {
  code=$?
  if [ "$code" -eq 1 ]; then
    echo "Supply chain findings detected"
    exit 1
  elif [ "$code" -eq 2 ]; then
    echo "Scanner error"
    exit 2
  fi
}
```

## CI/CD Integration

### GitHub Actions (text output)

```yaml
name: Supply Chain Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: pnpm install --frozen-lockfile
      - run: npx @digi4care/shai-scan --severity high .
```

### GitHub Actions (SARIF upload)

```yaml
name: Supply Chain Scan SARIF
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: pnpm install --frozen-lockfile
      - run: npx @digi4care/shai-scan --sarif --sarif-file results.sarif .
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Text   | (default) | Human-readable table of findings with severity, package name, version, and campaign details |
| JSON   | `--json` | Structured JSON array of findings, suitable for ingestion into SIEMs or custom dashboards |
| SARIF  | `--sarif` | OASIS SARIF 2.1.0 format for upload to GitHub Code Scanning, GitLab Secure, or other SARIF consumers |

Example JSON excerpt:

```json
[
  {
    "package": "@tanstack/react-router",
    "version": "1.169.5",
    "ecosystem": "npm",
    "severity": "critical",
    "campaign": "mini-shai-hulud-wave4",
    "cve": "CVE-2026-45321",
    "reference": "https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx"
  }
]
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | No compromised packages or IOCs detected |
| 1    | One or more findings detected |
| 2    | Runtime error (invalid path, unreadable lockfile, etc.) |

## Adding New Campaigns

When a new supply chain attack is discovered, update `src/db.ts`:

1. Add a new `CompromisedVersion[]` array with the affected packages and versions
2. Append a new `Campaign` object to the `CAMPAIGNS` array, including CVE/GHSA identifiers, severity, description, reference URLs, and IOC indicators
3. The `buildLookup()` function automatically rebuilds the lookup map on the next run

No rebuild step is required. Changes to `src/db.ts` take effect immediately — the project runs TypeScript directly via Node.js (v22+) or Bun.

## Security Considerations

- **Zero runtime dependencies**: The scanner uses only Node.js/Bun built-in modules. It does not download or execute third-party code at runtime, eliminating the risk that the scanner itself becomes a compromise vector.
- **pnpm as package manager**: pnpm uses strict lockfiles, does not execute lifecycle scripts by default, and supports content-addressable storage. These properties reduce the attack surface compared to other package managers.
- **Recommended `.npmrc` settings**: For maximum protection when installing packages, add the following to your project or global `.npmrc`:

  ```ini
  ignore-scripts=true
  engine-strict=true
  ```

- **No network calls**: `shai-scan` does not phone home, download signatures, or require an API key. All campaign data is shipped with the package.

## Affected Packages (Current Campaign)

The following packages and versions are known to be compromised in **CVE-2026-45321** (Mini Shai-Hulud Wave 4). This is a representative subset; the full list is maintained in `src/db.ts`.

| Package | Ecosystem | Compromised Versions |
|---------|-----------|---------------------|
| `@tanstack/react-router` | npm | 1.169.5, 1.169.8 |
| `@tanstack/vue-router` | npm | 1.169.5, 1.169.8 |
| `@tanstack/solid-router` | npm | 1.169.5, 1.169.8 |
| `@tanstack/router-core` | npm | 1.169.5, 1.169.8 |
| `@tanstack/react-start` | npm | 1.167.68, 1.167.71 |
| `@mistralai/mistralai` | npm | 2.2.2, 2.2.3, 2.2.4 |
| `@mistralai/mistralai-azure` | npm | 1.7.2, 1.7.3 |
| `mistralai` | pypi | 2.4.6 |
| `@opensearch-project/opensearch` | npm | 3.5.3, 3.6.2, 3.7.0, 3.8.0 |
| `@uipath/robot` | npm | 1.3.4 |
| `@squawk/airways` | npm | 0.4.2, 0.4.3, 0.4.5 |
| `@draftauth/core` | npm | 0.13.1, 0.13.2 |
| `@tallyui/core` | npm | 0.2.1, 0.2.2, 0.2.3 |
| `safe-action` | npm | 0.8.3, 0.8.4 |
| `cmux-agent-mcp` | npm | 0.1.3 - 0.1.8 |
| `nextmove-mcp` | npm | 0.1.3, 0.1.4, 0.1.5, 0.1.7 |
| `ts-dna` | npm | 3.0.1, 3.0.2, 3.0.4 |
| `cross-stitch` | npm | 1.1.3, 1.1.4, 1.1.6 |
| `git-git-git` | npm | 1.0.8 - 1.0.12 |
| `git-branch-selector` | npm | 1.3.3 - 1.3.7 |
| `agentwork-cli` | npm | 0.1.4, 0.1.5 |
| `wot-api` | npm | 0.8.1, 0.8.2, 0.8.4 |
| `ml-toolkit-ts` | npm | 1.0.4, 1.0.5 |
| `@beproduct/nestjs-auth` | npm | 0.1.2 - 0.1.19 |
| `@dirigible-ai/sdk` | npm | 0.6.2, 0.6.3 |
| `@taskflow-corp/cli` | npm | 0.1.24 - 0.1.29 |
| `@tolka/cli` | npm | 1.0.2, 1.0.3, 1.0.4, 1.0.6 |
| `@supersurkhet/cli` | npm | 0.0.2 - 0.0.7 |
| `guardrails-ai` | pypi | 0.10.1 |

## License

MIT. See [LICENSE](LICENSE) for details.

## Disclaimer

`shai-scan` is a detection aid, not a substitute for comprehensive security audits, dependency review, or threat intelligence platforms. It identifies known compromised versions based on the shipped database; novel or zero-day supply chain attacks may not be detected until a campaign is added. Always practice defense in depth: audit dependencies, pin versions, verify provenance, and monitor CI/CD pipelines.
