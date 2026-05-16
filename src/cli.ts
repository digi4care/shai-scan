#!/usr/bin/env node
/**
 * CLI entry point for shai-scan.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CAMPAIGNS } from "./db.js";
import { type LockfileFinding, type ScanOptions, type ScanResult, scan } from "./scanner.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(resolve(__dirname, "..", "package.json"), "utf-8")).version;

// ── ANSI colors ────────────────────────────────────────────────────────────

interface Colors {
	reset: string;
	bold: string;
	red: string;
	yellow: string;
	green: string;
	cyan: string;
	gray: string;
}

function getColors(enabled: boolean): Colors {
	if (!enabled) {
		return { reset: "", bold: "", red: "", yellow: "", green: "", cyan: "", gray: "" };
	}
	return {
		reset: "\x1b[0m",
		bold: "\x1b[1m",
		red: "\x1b[31m",
		yellow: "\x1b[33m",
		green: "\x1b[32m",
		cyan: "\x1b[36m",
		gray: "\x1b[90m",
	};
}

// ── Arg parsing ────────────────────────────────────────────────────────────

interface ParsedArgs {
	rootPath: string;
	json: boolean;
	sarif: boolean;
	sarifFile: string | null;
	text: boolean;
	severity: string | null;
	lockfilesOnly: boolean;
	systemOnly: boolean;
	noColor: boolean;
	help: boolean;
	version: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
	const args: ParsedArgs = {
		rootPath: process.cwd(),
		json: false,
		sarif: false,
		sarifFile: null,
		text: false,
		severity: null,
		lockfilesOnly: false,
		systemOnly: false,
		noColor: false,
		help: false,
		version: false,
	};

	let positionalSet = false;

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];

		switch (arg) {
			case "--json":
				args.json = true;
				break;
			case "--sarif":
				args.sarif = true;
				break;
			case "--sarif-file":
				args.sarifFile = argv[++i] ?? null;
				break;
			case "--text":
				args.text = true;
				break;
			case "--severity":
				args.severity = argv[++i] ?? null;
				break;
			case "--lockfiles-only":
				args.lockfilesOnly = true;
				break;
			case "--system-only":
				args.systemOnly = true;
				break;
			case "--no-color":
				args.noColor = true;
				break;
			case "-h":
			case "--help":
				args.help = true;
				break;
			case "-V":
			case "--version":
				args.version = true;
				break;
			default:
				if (!arg.startsWith("-") && !positionalSet) {
					args.rootPath = resolve(arg);
					positionalSet = true;
				}
				break;
		}
	}

	return args;
}

function showHelp(): void {
	console.log(`shai-scan v${VERSION} — Supply chain compromise scanner`);
	console.log("");
	console.log("Usage: shai-scan [path] [options]");
	console.log("");
	console.log("Options:");
	console.log("  --json              Output results as JSON");
	console.log("  --sarif             Output results as SARIF");
	console.log("  --sarif-file <path> Write SARIF to file");
	console.log("  --text              Output human-readable text (default)");
	console.log("  --severity <level>  Minimum severity: critical, high, medium, low");
	console.log("  --lockfiles-only    Skip system checks");
	console.log("  --system-only       Skip lockfile scanning");
	console.log("  --no-color          Disable ANSI colors");
	console.log("  -h, --help          Show this help");
	console.log("  -V, --version       Show version");
}

function showVersion(): void {
	console.log(VERSION);
}

// ── Output formatters ──────────────────────────────────────────────────────

function formatText(result: ScanResult, rootPath: string, colors: Colors): string {
	const lines: string[] = [];

	lines.push(`${colors.bold}shai-scan${colors.reset} — Supply Chain Compromise Scanner`);
	lines.push(`${colors.gray}Root:${colors.reset} ${rootPath}`);
	lines.push("");

	// Lockfile findings
	if (result.lockfileFindings.length > 0) {
		lines.push(`${colors.bold}Lockfile Findings:${colors.reset}`);

		const byLockfile = new Map<string, LockfileFinding[]>();
		for (const f of result.lockfileFindings) {
			const arr = byLockfile.get(f.lockfile) ?? [];
			arr.push(f);
			byLockfile.set(f.lockfile, arr);
		}

		for (const [lockfile, findings] of byLockfile) {
			lines.push(`  ${colors.cyan}${lockfile}${colors.reset}`);
			for (const f of findings) {
				const sevColor = f.severity === "critical" ? colors.red : f.severity === "high" ? colors.yellow : colors.gray;
				lines.push(
					`    ${sevColor}[${f.severity.toUpperCase()}]${colors.reset} ${f.packageName}@${f.version} — ${f.campaign.name}`,
				);
			}
		}
		lines.push("");
	}

	// System findings
	const notableSystem = result.systemFindings.filter(
		(f) => f.status === "infected" || f.status === "suspicious" || f.status === "error",
	);
	if (notableSystem.length > 0) {
		lines.push(`${colors.bold}System Findings:${colors.reset}`);
		for (const f of notableSystem) {
			const sevColor = f.severity === "critical" ? colors.red : f.severity === "high" ? colors.yellow : colors.gray;
			const statusColor =
				f.status === "infected" ? colors.red : f.status === "suspicious" ? colors.yellow : colors.gray;
			lines.push(
				`  ${statusColor}[${f.status.toUpperCase()}]${colors.reset} ${sevColor}[${f.severity.toUpperCase()}]${colors.reset} ${f.check}`,
			);
			lines.push(`    ${f.detail}`);
		}
		lines.push("");
	}

	// Summary
	const infectedCount = result.lockfileFindings.length;
	const sysIssues = result.systemFindings.filter((f) => f.status === "infected" || f.status === "suspicious").length;

	lines.push(`${colors.bold}Summary:${colors.reset}`);
	lines.push(`  Lockfiles scanned: ${result.lockfilesScanned}`);
	lines.push(`  Compromised packages: ${infectedCount}`);
	lines.push(`  System issues: ${sysIssues}`);
	if (result.errors.length > 0) {
		lines.push(`  Errors: ${result.errors.length}`);
		for (const err of result.errors) {
			lines.push(`    ${colors.gray}${err}${colors.reset}`);
		}
	}

	if (infectedCount === 0 && sysIssues === 0) {
		lines.push("");
		lines.push(`${colors.green}No compromises detected.${colors.reset}`);
	} else {
		lines.push("");
		lines.push(`${colors.red}COMPROMISE DETECTED — immediate action recommended.${colors.reset}`);
	}

	return lines.join("\n");
}

function formatJson(result: ScanResult, rootPath: string): string {
	const infectedCount = result.lockfileFindings.length;
	const sysIssues = result.systemFindings.filter((f) => f.status === "infected" || f.status === "suspicious").length;

	const payload = {
		version: VERSION,
		timestamp: new Date().toISOString(),
		rootPath,
		findings: {
			lockfile: result.lockfileFindings.map((f) => ({
				lockfile: f.lockfile,
				packageName: f.packageName,
				version: f.version,
				severity: f.severity,
				campaign: {
					id: f.campaign.id,
					name: f.campaign.name,
					cve: f.campaign.cve,
					ghsa: f.campaign.ghsa,
				},
			})),
			system: result.systemFindings.filter(
				(f) => f.status === "infected" || f.status === "suspicious" || f.status === "error",
			),
		},
		summary: {
			lockfilesScanned: result.lockfilesScanned,
			compromisedPackages: infectedCount,
			systemIssues: sysIssues,
			errors: result.errors.length,
		},
		exitCode: infectedCount > 0 || sysIssues > 0 ? 1 : 0,
	};

	return JSON.stringify(payload, null, 2);
}

function formatSarif(result: ScanResult, rootPath: string): string {
	const rules: Array<Record<string, unknown>> = [];
	const results: Array<Record<string, unknown>> = [];

	for (const campaign of CAMPAIGNS) {
		rules.push({
			id: campaign.id,
			name: campaign.name,
			shortDescription: { text: campaign.description.slice(0, 200) },
			fullDescription: { text: campaign.description },
			defaultConfiguration: {
				level: campaign.severity === "critical" ? "error" : campaign.severity === "high" ? "error" : "warning",
			},
			properties: {
				severity: campaign.severity,
				cve: campaign.cve,
				ghsa: campaign.ghsa,
				referenceUrls: campaign.referenceUrls,
			},
		});
	}

	for (const finding of result.lockfileFindings) {
		results.push({
			ruleId: finding.campaign.id,
			level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning",
			message: {
				text: `Compromised package ${finding.packageName}@${finding.version} found in ${finding.lockfile}`,
			},
			locations: [
				{
					physicalLocation: {
						artifactLocation: {
							uri: finding.lockfile,
							uriBaseId: "%SRCROOT%",
						},
					},
				},
			],
			properties: {
				packageName: finding.packageName,
				version: finding.version,
				campaign: finding.campaign.name,
				severity: finding.severity,
			},
		});
	}

	for (const sys of result.systemFindings) {
		if (sys.status !== "infected" && sys.status !== "suspicious") continue;
		results.push({
			ruleId: sys.campaign.split(", ")[0] ?? "unknown",
			level: sys.severity === "critical" || sys.severity === "high" ? "error" : "warning",
			message: { text: `${sys.check}: ${sys.detail}` },
			properties: {
				check: sys.check,
				status: sys.status,
				severity: sys.severity,
				campaign: sys.campaign,
			},
		});
	}

	const sarif = {
		$schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "shai-scan",
						version: VERSION,
						informationUri: "https://github.com/shai-scan/shai-scan",
						rules,
					},
				},
				results,
				invocations: [
					{
						executionSuccessful: result.errors.length === 0,
					},
				],
				originalUriBaseIds: {
					"%SRCROOT%": {
						uri: `file://${rootPath}/`,
					},
				},
			},
		],
	};

	return JSON.stringify(sarif, null, 2);
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
	const args = parseArgs(process.argv.slice(2));

	if (args.help) {
		showHelp();
		process.exit(0);
	}

	if (args.version) {
		showVersion();
		process.exit(0);
	}

	const useColor = !args.noColor && !process.env.NO_COLOR;
	const colors = getColors(useColor);

	const options: ScanOptions = {
		lockfilesOnly: args.lockfilesOnly,
		systemOnly: args.systemOnly,
		minSeverity: args.severity ?? undefined,
	};

	let result: ScanResult;
	try {
		result = await scan(args.rootPath, options);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.error(`${colors.red}Fatal error:${colors.reset} ${msg}`);
		process.exit(2);
	}

	// Determine output format
	let output = "";
	if (args.json) {
		output = formatJson(result, args.rootPath);
	} else if (args.sarif || args.sarifFile) {
		output = formatSarif(result, args.rootPath);
	} else {
		output = formatText(result, args.rootPath, colors);
	}

	console.log(output);

	if (args.sarifFile) {
		try {
			writeFileSync(args.sarifFile, output, "utf-8");
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			console.error(`${colors.red}Failed to write SARIF file:${colors.reset} ${msg}`);
			process.exit(2);
		}
	}

	const hasFindings =
		result.lockfileFindings.length > 0 ||
		result.systemFindings.some((f) => f.status === "infected" || f.status === "suspicious");

	process.exit(hasFindings ? 1 : 0);
}

main();
