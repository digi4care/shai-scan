/**
 * Scan orchestration: lockfile discovery, parsing, and IOC correlation.
 */

import { readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { buildLookup, type Campaign } from "./db.js";
import { parseLockfile } from "./lockfile.js";
import { runSystemChecks, type SystemCheckResult } from "./system.js";

export interface ScanOptions {
	lockfilesOnly?: boolean;
	systemOnly?: boolean;
	minSeverity?: string;
}

export interface LockfileFinding {
	lockfile: string;
	packageName: string;
	version: string;
	campaign: Campaign;
	severity: string;
}

export interface ScanResult {
	lockfileFindings: LockfileFinding[];
	systemFindings: SystemCheckResult[];
	lockfilesScanned: number;
	errors: string[];
}

const LOCKFILE_NAMES = new Set([
	"package-lock.json",
	"bun.lock",
	"pnpm-lock.yaml",
	"requirements.txt",
	"Pipfile.lock",
	"poetry.lock",
]);

const MAX_DEPTH = 5;

async function findLockfiles(root: string): Promise<string[]> {
	const results: string[] = [];

	async function walk(dir: string, depth: number): Promise<void> {
		if (depth > MAX_DEPTH) return;

		let entries: Array<{ name: string; isDirectory(): boolean }>;
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			return;
		}

		for (const entry of entries) {
			if (entry.name === "node_modules") continue;
			const full = join(dir, entry.name);
			if (entry.isDirectory()) {
				await walk(full, depth + 1);
			} else if (LOCKFILE_NAMES.has(entry.name)) {
				results.push(full);
			}
		}
	}

	try {
		const s = await stat(root);
		if (!s.isDirectory()) {
			// If root itself is a lockfile, scan it
			const name = root.split("/").pop() ?? "";
			if (LOCKFILE_NAMES.has(name)) {
				results.push(root);
			}
			return results;
		}
	} catch {
		return results;
	}

	await walk(root, 0);
	return results;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

function severityIndex(sev: string): number {
	return SEVERITY_ORDER.indexOf(sev.toLowerCase());
}

function passesMinSeverity(severity: string, minSeverity?: string): boolean {
	if (!minSeverity) return true;
	return severityIndex(severity) <= severityIndex(minSeverity);
}

export async function scan(rootPath: string, options: ScanOptions = {}): Promise<ScanResult> {
	const result: ScanResult = {
		lockfileFindings: [],
		systemFindings: [],
		lockfilesScanned: 0,
		errors: [],
	};

	const lookup = buildLookup();

	// Lockfile scanning
	if (!options.systemOnly) {
		const lockfilePaths = await findLockfiles(rootPath);

		for (const filePath of lockfilePaths) {
			const parsed = await parseLockfile(filePath);
			if (parsed === null) {
				result.errors.push(`Failed to parse lockfile: ${relative(rootPath, filePath) || filePath}`);
				continue;
			}

			result.lockfilesScanned++;

			for (const [pkgName, version] of parsed.packages) {
				const entries = lookup.get(pkgName);
				if (!entries) continue;

				for (const entry of entries) {
					if (entry.compromisedVersions.has(version)) {
						const sev = entry.campaign.severity;
						if (passesMinSeverity(sev, options.minSeverity)) {
							result.lockfileFindings.push({
								lockfile: relative(rootPath, filePath) || filePath,
								packageName: pkgName,
								version,
								campaign: entry.campaign,
								severity: sev,
							});
						}
					}
				}
			}
		}
	}

	// System checks
	if (!options.lockfilesOnly) {
		try {
			result.systemFindings = runSystemChecks([rootPath]);
			if (options.minSeverity) {
				result.systemFindings = result.systemFindings.filter((f) => passesMinSeverity(f.severity, options.minSeverity));
			}
		} catch (err) {
			result.errors.push(`System check error: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	return result;
}
