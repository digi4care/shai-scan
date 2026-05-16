/**
 * Compromised package database for supply chain attacks.
 *
 * Update this file when new campaigns are discovered.
 * Each campaign groups packages by attack wave.
 */

export interface CompromisedVersion {
	name: string;
	versions: string[];
	ecosystem: "npm" | "pypi";
}

export interface IOCIndicators {
	domains: string[];
	ips: string[];
	files: string[];
	services: string[];
	npmTokenDescriptions: string[];
	/** Paths where the malware installs persistence hooks */
	persistencePaths: string[];
}

export interface Campaign {
	id: string;
	name: string;
	date: string;
	attribution: string;
	cve?: string;
	ghsa?: string;
	severity: "critical" | "high" | "medium";
	description: string;
	referenceUrls: string[];
	packages: CompromisedVersion[];
	iocs: IOCIndicators;
}

// ── Campaign: Mini Shai-Hulud Wave 4 (May 11, 2026) ──────────────────────

const MINI_SHAI_HULUD_W4_PACKAGES: CompromisedVersion[] = [
	// ── TanStack (42 packages, 84 versions) ──
	{ name: "@tanstack/react-router", versions: ["1.169.5", "1.169.8"], ecosystem: "npm" },
	{ name: "@tanstack/vue-router", versions: ["1.169.5", "1.169.8"], ecosystem: "npm" },
	{ name: "@tanstack/solid-router", versions: ["1.169.5", "1.169.8"], ecosystem: "npm" },
	{ name: "@tanstack/router-core", versions: ["1.169.5", "1.169.8"], ecosystem: "npm" },
	{ name: "@tanstack/react-start", versions: ["1.167.68", "1.167.71"], ecosystem: "npm" },
	{ name: "@tanstack/router-plugin", versions: ["1.167.38", "1.167.41"], ecosystem: "npm" },
	{ name: "@tanstack/router-utils", versions: ["1.161.11", "1.161.14"], ecosystem: "npm" },
	{ name: "@tanstack/router-cli", versions: ["1.166.46", "1.166.49"], ecosystem: "npm" },
	{ name: "@tanstack/router-devtools", versions: ["1.166.16", "1.166.19"], ecosystem: "npm" },
	{ name: "@tanstack/router-devtools-core", versions: ["1.167.6", "1.167.9"], ecosystem: "npm" },
	{ name: "@tanstack/router-generator", versions: ["1.166.45", "1.166.48"], ecosystem: "npm" },
	{ name: "@tanstack/router-vite-plugin", versions: ["1.166.53", "1.166.56"], ecosystem: "npm" },
	{ name: "@tanstack/router-ssr-query-core", versions: ["1.168.3", "1.168.6"], ecosystem: "npm" },
	{ name: "@tanstack/history", versions: ["1.161.9", "1.161.12"], ecosystem: "npm" },
	{ name: "@tanstack/react-router-devtools", versions: ["1.166.16", "1.166.19"], ecosystem: "npm" },
	{ name: "@tanstack/react-router-ssr-query", versions: ["1.166.15", "1.166.18"], ecosystem: "npm" },
	{ name: "@tanstack/react-start-client", versions: ["1.166.51", "1.166.54"], ecosystem: "npm" },
	{ name: "@tanstack/react-start-server", versions: ["1.166.55", "1.166.58"], ecosystem: "npm" },
	{ name: "@tanstack/react-start-rsc", versions: ["0.0.47", "0.0.50"], ecosystem: "npm" },
	{ name: "@tanstack/solid-router-devtools", versions: ["1.166.16", "1.166.19"], ecosystem: "npm" },
	{ name: "@tanstack/solid-router-ssr-query", versions: ["1.166.15", "1.166.18"], ecosystem: "npm" },
	{ name: "@tanstack/solid-start", versions: ["1.167.65", "1.167.68"], ecosystem: "npm" },
	{ name: "@tanstack/solid-start-client", versions: ["1.166.50", "1.166.53"], ecosystem: "npm" },
	{ name: "@tanstack/solid-start-server", versions: ["1.166.54", "1.166.57"], ecosystem: "npm" },
	{ name: "@tanstack/vue-router-devtools", versions: ["1.166.16", "1.166.19"], ecosystem: "npm" },
	{ name: "@tanstack/vue-router-ssr-query", versions: ["1.166.15", "1.166.18"], ecosystem: "npm" },
	{ name: "@tanstack/vue-start", versions: ["1.167.61", "1.167.64"], ecosystem: "npm" },
	{ name: "@tanstack/vue-start-client", versions: ["1.166.46", "1.166.49"], ecosystem: "npm" },
	{ name: "@tanstack/vue-start-server", versions: ["1.166.50", "1.166.53"], ecosystem: "npm" },
	{ name: "@tanstack/start-client-core", versions: ["1.168.5", "1.168.8"], ecosystem: "npm" },
	{ name: "@tanstack/start-server-core", versions: ["1.167.33", "1.167.36"], ecosystem: "npm" },
	{ name: "@tanstack/start-plugin-core", versions: ["1.169.23", "1.169.26"], ecosystem: "npm" },
	{ name: "@tanstack/start-fn-stubs", versions: ["1.161.9", "1.161.12"], ecosystem: "npm" },
	{ name: "@tanstack/start-storage-context", versions: ["1.166.38", "1.166.41"], ecosystem: "npm" },
	{ name: "@tanstack/start-static-server-functions", versions: ["1.166.44", "1.166.47"], ecosystem: "npm" },
	{ name: "@tanstack/virtual-file-routes", versions: ["1.161.10", "1.161.13"], ecosystem: "npm" },
	{ name: "@tanstack/arktype-adapter", versions: ["1.166.12", "1.166.15"], ecosystem: "npm" },
	{ name: "@tanstack/valibot-adapter", versions: ["1.166.12", "1.166.15"], ecosystem: "npm" },
	{ name: "@tanstack/zod-adapter", versions: ["1.166.12", "1.166.15"], ecosystem: "npm" },
	{ name: "@tanstack/eslint-plugin-router", versions: ["1.161.9", "1.161.12"], ecosystem: "npm" },
	{ name: "@tanstack/eslint-plugin-start", versions: ["0.0.4", "0.0.7"], ecosystem: "npm" },
	{ name: "@tanstack/nitro-v2-vite-plugin", versions: ["1.154.12", "1.154.15"], ecosystem: "npm" },

	// ── Mistral AI ──
	{ name: "@mistralai/mistralai", versions: ["2.2.2", "2.2.3", "2.2.4"], ecosystem: "npm" },
	{ name: "@mistralai/mistralai-azure", versions: ["1.7.2", "1.7.3"], ecosystem: "npm" },
	{ name: "@mistralai/mistralai-gcp", versions: ["1.7.2", "1.7.3"], ecosystem: "npm" },
	{ name: "mistralai", versions: ["2.4.6"], ecosystem: "pypi" },

	// ── OpenSearch ──
	{ name: "@opensearch-project/opensearch", versions: ["3.5.3", "3.6.2", "3.7.0", "3.8.0"], ecosystem: "npm" },

	// ── UiPath ──
	{ name: "@uipath/docsai-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-apiworkflow", versions: ["0.0.19"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-workflowcompiler-browser", versions: ["0.0.34"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-functions", versions: ["0.1.1"], ecosystem: "npm" },
	{ name: "@uipath/agent.sdk", versions: ["0.0.18"], ecosystem: "npm" },
	{ name: "@uipath/filesystem", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/admin-tool", versions: ["0.1.1"], ecosystem: "npm" },
	{ name: "@uipath/llmgw-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/access-policy-sdk", versions: ["0.3.1"], ecosystem: "npm" },
	{ name: "@uipath/access-policy-tool", versions: ["0.3.1"], ecosystem: "npm" },
	{ name: "@uipath/agent-sdk", versions: ["1.0.2"], ecosystem: "npm" },
	{ name: "@uipath/agent-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/aops-policy-tool", versions: ["0.3.1"], ecosystem: "npm" },
	{ name: "@uipath/ap-chat", versions: ["1.5.7"], ecosystem: "npm" },
	{ name: "@uipath/api-workflow-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/apollo-core", versions: ["5.9.2"], ecosystem: "npm" },
	{ name: "@uipath/apollo-react", versions: ["4.24.5"], ecosystem: "npm" },
	{ name: "@uipath/apollo-wind", versions: ["2.16.2"], ecosystem: "npm" },
	{ name: "@uipath/auth", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/case-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/cli", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/codedagent-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/codedagents-tool", versions: ["0.1.12"], ecosystem: "npm" },
	{ name: "@uipath/codedapp-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/common", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/context-grounding-tool", versions: ["0.1.1"], ecosystem: "npm" },
	{ name: "@uipath/data-fabric-tool", versions: ["1.0.2"], ecosystem: "npm" },
	{ name: "@uipath/flow-tool", versions: ["1.0.2"], ecosystem: "npm" },
	{ name: "@uipath/functions-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/gov-tool", versions: ["0.3.1"], ecosystem: "npm" },
	{ name: "@uipath/identity-tool", versions: ["0.1.1"], ecosystem: "npm" },
	{ name: "@uipath/insights-sdk", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/insights-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/integrationservice-sdk", versions: ["1.0.2"], ecosystem: "npm" },
	{ name: "@uipath/integrationservice-tool", versions: ["1.0.2"], ecosystem: "npm" },
	{ name: "@uipath/maestro-sdk", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/maestro-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/orchestrator-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-bpmn", versions: ["0.0.9"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-case", versions: ["0.0.9"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-connector", versions: ["0.0.19"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-flow", versions: ["0.0.19"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-webapp", versions: ["1.0.6"], ecosystem: "npm" },
	{ name: "@uipath/packager-tool-workflowcompiler", versions: ["0.0.16"], ecosystem: "npm" },
	{ name: "@uipath/platform-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/project-packager", versions: ["1.1.16"], ecosystem: "npm" },
	{ name: "@uipath/resource-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/resourcecatalog-tool", versions: ["0.1.1"], ecosystem: "npm" },
	{ name: "@uipath/resources-tool", versions: ["0.1.11"], ecosystem: "npm" },
	{ name: "@uipath/robot", versions: ["1.3.4"], ecosystem: "npm" },
	{ name: "@uipath/rpa-legacy-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/rpa-tool", versions: ["0.9.5"], ecosystem: "npm" },
	{ name: "@uipath/solution-packager", versions: ["0.0.35"], ecosystem: "npm" },
	{ name: "@uipath/solution-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/solutionpackager-sdk", versions: ["1.0.11"], ecosystem: "npm" },
	{ name: "@uipath/solutionpackager-tool-core", versions: ["0.0.34"], ecosystem: "npm" },
	{ name: "@uipath/tasks-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/telemetry", versions: ["0.0.7"], ecosystem: "npm" },
	{ name: "@uipath/test-manager-tool", versions: ["1.0.2"], ecosystem: "npm" },
	{ name: "@uipath/tool-workflowcompiler", versions: ["0.0.12"], ecosystem: "npm" },
	{ name: "@uipath/traces-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/ui-widgets-multi-file-upload", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/uipath-python-bridge", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/vertical-solutions-tool", versions: ["1.0.1"], ecosystem: "npm" },
	{ name: "@uipath/vss", versions: ["0.1.6"], ecosystem: "npm" },
	{ name: "@uipath/widget.sdk", versions: ["1.2.3"], ecosystem: "npm" },

	// ── Squawk (aviation) ──
	{ name: "@squawk/airways", versions: ["0.4.2", "0.4.3", "0.4.5"], ecosystem: "npm" },
	{ name: "@squawk/airport-data", versions: ["0.7.4", "0.7.5", "0.7.7"], ecosystem: "npm" },
	{ name: "@squawk/airports", versions: ["0.6.2", "0.6.3", "0.6.5"], ecosystem: "npm" },
	{ name: "@squawk/airspace", versions: ["0.8.1", "0.8.2", "0.8.4"], ecosystem: "npm" },
	{ name: "@squawk/airspace-data", versions: ["0.5.3", "0.5.4", "0.5.6"], ecosystem: "npm" },
	{ name: "@squawk/airway-data", versions: ["0.5.4", "0.5.5", "0.5.7"], ecosystem: "npm" },
	{ name: "@squawk/fix-data", versions: ["0.6.4", "0.6.5", "0.6.7"], ecosystem: "npm" },
	{ name: "@squawk/fixes", versions: ["0.3.2", "0.3.3", "0.3.5"], ecosystem: "npm" },
	{ name: "@squawk/flight-math", versions: ["0.5.4", "0.5.5", "0.5.7"], ecosystem: "npm" },
	{ name: "@squawk/flightplan", versions: ["0.5.2", "0.5.3", "0.5.5"], ecosystem: "npm" },
	{ name: "@squawk/geo", versions: ["0.4.4", "0.4.5", "0.4.7"], ecosystem: "npm" },
	{ name: "@squawk/icao-registry", versions: ["0.5.2", "0.5.3", "0.5.5"], ecosystem: "npm" },
	{ name: "@squawk/icao-registry-data", versions: ["0.8.4", "0.8.5", "0.8.7"], ecosystem: "npm" },
	{ name: "@squawk/mcp", versions: ["0.9.1", "0.9.2", "0.9.4"], ecosystem: "npm" },
	{ name: "@squawk/navaid-data", versions: ["0.6.4", "0.6.5", "0.6.7"], ecosystem: "npm" },
	{ name: "@squawk/navaids", versions: ["0.4.2", "0.4.3", "0.4.5"], ecosystem: "npm" },
	{ name: "@squawk/notams", versions: ["0.3.6", "0.3.7", "0.3.9"], ecosystem: "npm" },
	{ name: "@squawk/procedure-data", versions: ["0.7.3", "0.7.4", "0.7.6"], ecosystem: "npm" },
	{ name: "@squawk/procedures", versions: ["0.5.2", "0.5.3", "0.5.5"], ecosystem: "npm" },
	{ name: "@squawk/types", versions: ["0.8.1", "0.8.2", "0.8.4"], ecosystem: "npm" },
	{ name: "@squawk/units", versions: ["0.4.3", "0.4.4", "0.4.6"], ecosystem: "npm" },
	{ name: "@squawk/weather", versions: ["0.5.6", "0.5.7", "0.5.9"], ecosystem: "npm" },

	// ── DraftLab / DraftAuth ──
	{ name: "@draftauth/client", versions: ["0.2.1", "0.2.2"], ecosystem: "npm" },
	{ name: "@draftauth/core", versions: ["0.13.1", "0.13.2"], ecosystem: "npm" },
	{ name: "@draftlab/auth", versions: ["0.24.1", "0.24.2"], ecosystem: "npm" },
	{ name: "@draftlab/auth-router", versions: ["0.5.1", "0.5.2"], ecosystem: "npm" },
	{ name: "@draftlab/db", versions: ["0.16.1", "0.16.2"], ecosystem: "npm" },

	// ── TallyUI ──
	{ name: "@tallyui/components", versions: ["1.0.1", "1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@tallyui/connector-medusa", versions: ["1.0.1", "1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@tallyui/connector-shopify", versions: ["1.0.1", "1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@tallyui/connector-vendure", versions: ["1.0.1", "1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@tallyui/connector-woocommerce", versions: ["1.0.1", "1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@tallyui/core", versions: ["0.2.1", "0.2.2", "0.2.3"], ecosystem: "npm" },
	{ name: "@tallyui/database", versions: ["1.0.1", "1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@tallyui/pos", versions: ["0.1.1", "0.1.2", "0.1.3"], ecosystem: "npm" },
	{ name: "@tallyui/storage-sqlite", versions: ["0.2.1", "0.2.2", "0.2.3"], ecosystem: "npm" },
	{ name: "@tallyui/theme", versions: ["0.2.1", "0.2.2", "0.2.3"], ecosystem: "npm" },

	// ── Miscellaneous npm packages ──
	{ name: "safe-action", versions: ["0.8.3", "0.8.4"], ecosystem: "npm" },
	{ name: "cmux-agent-mcp", versions: ["0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8"], ecosystem: "npm" },
	{ name: "nextmove-mcp", versions: ["0.1.3", "0.1.4", "0.1.5", "0.1.7"], ecosystem: "npm" },
	{ name: "ts-dna", versions: ["3.0.1", "3.0.2", "3.0.4"], ecosystem: "npm" },
	{ name: "cross-stitch", versions: ["1.1.3", "1.1.4", "1.1.6"], ecosystem: "npm" },
	{ name: "git-git-git", versions: ["1.0.8", "1.0.9", "1.0.10", "1.0.12"], ecosystem: "npm" },
	{ name: "git-branch-selector", versions: ["1.3.3", "1.3.4", "1.3.5", "1.3.7"], ecosystem: "npm" },
	{ name: "agentwork-cli", versions: ["0.1.4", "0.1.5"], ecosystem: "npm" },
	{ name: "wot-api", versions: ["0.8.1", "0.8.2", "0.8.4"], ecosystem: "npm" },
	{ name: "ml-toolkit-ts", versions: ["1.0.4", "1.0.5"], ecosystem: "npm" },
	{
		name: "@beproduct/nestjs-auth",
		versions: [
			"0.1.2",
			"0.1.3",
			"0.1.4",
			"0.1.5",
			"0.1.6",
			"0.1.7",
			"0.1.8",
			"0.1.9",
			"0.1.10",
			"0.1.11",
			"0.1.12",
			"0.1.13",
			"0.1.14",
			"0.1.15",
			"0.1.16",
			"0.1.17",
			"0.1.19",
		],
		ecosystem: "npm",
	},
	{ name: "@dirigible-ai/sdk", versions: ["0.6.2", "0.6.3"], ecosystem: "npm" },
	{ name: "@ml-toolkit-ts/preprocessing", versions: ["1.0.2", "1.0.3"], ecosystem: "npm" },
	{ name: "@ml-toolkit-ts/xgboost", versions: ["1.0.3", "1.0.4"], ecosystem: "npm" },
	{ name: "@mesadev/rest", versions: ["0.28.3"], ecosystem: "npm" },
	{ name: "@mesadev/saguaro", versions: ["0.4.22"], ecosystem: "npm" },
	{ name: "@mesadev/sdk", versions: ["0.28.3"], ecosystem: "npm" },

	// ── Misc. scoped ──
	{
		name: "@taskflow-corp/cli",
		versions: ["0.1.24", "0.1.25", "0.1.26", "0.1.27", "0.1.28", "0.1.29"],
		ecosystem: "npm",
	},
	{ name: "@tolka/cli", versions: ["1.0.2", "1.0.3", "1.0.4", "1.0.6"], ecosystem: "npm" },
	{ name: "@supersurkhet/cli", versions: ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"], ecosystem: "npm" },
	{ name: "@supersurkhet/sdk", versions: ["0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "0.0.7"], ecosystem: "npm" },

	// ── PyPI ──
	{ name: "guardrails-ai", versions: ["0.10.1"], ecosystem: "pypi" },
];

export const CAMPAIGNS: Campaign[] = [
	{
		id: "mini-shai-hulud-wave4",
		name: "Mini Shai-Hulud Wave 4",
		date: "2026-05-11",
		attribution: "TeamPCP (aka DeadCatx3, PCPcat, ShellForce, CipherForce)",
		cve: "CVE-2026-45321",
		ghsa: "GHSA-g7cv-rxg3-hmpx",
		severity: "critical",
		description:
			"Self-propagating supply chain worm that hijacked GitHub Actions OIDC tokens to publish " +
			"malicious npm packages with valid SLSA Build Level 3 provenance. Stole credentials from " +
			"CI/CD pipelines, cloud providers, cryptocurrency wallets, and installed persistence hooks " +
			"in Claude Code and VS Code. Included a dead-man switch that wipes ~/ if npm tokens are revoked.",
		referenceUrls: [
			"https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html",
			"https://snyk.io/blog/tanstack-npm-packages-compromised/",
			"https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",
			"https://tanstack.com/blog/npm-supply-chain-compromise-postmortem",
			"https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx",
		],
		packages: MINI_SHAI_HULUD_W4_PACKAGES,
		iocs: {
			domains: ["filev2.getsession.org", "api.masscan.cloud", "git-tanstack.com"],
			ips: ["83.142.209.194"],
			files: ["router_init.js", "setup.mjs", "/tmp/transformers.pyz"],
			services: ["gh-token-monitor"],
			npmTokenDescriptions: ["IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"],
			persistencePaths: [".claude/settings.json", ".claude/settings.local.json", ".config/Code/User/settings.json"],
		},
	},
];

// ── Derived lookup structures ─────────────────────────────────────────────

export interface PackageLookupEntry {
	packageName: string;
	compromisedVersions: Set<string>;
	campaign: Campaign;
}

/** Build a map keyed by package name for O(1) lookup. */
export function buildLookup(): Map<string, PackageLookupEntry[]> {
	const map = new Map<string, PackageLookupEntry[]>();
	for (const campaign of CAMPAIGNS) {
		for (const pkg of campaign.packages) {
			const entry: PackageLookupEntry = {
				packageName: pkg.name,
				compromisedVersions: new Set(pkg.versions),
				campaign,
			};
			const existing = map.get(pkg.name) ?? [];
			existing.push(entry);
			map.set(pkg.name, existing);
		}
	}
	return map;
}
