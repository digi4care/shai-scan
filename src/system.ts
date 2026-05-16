/**
 * System IOC checks for supply chain compromise indicators.
 */

import { execSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { CAMPAIGNS, type Campaign } from "./db.js";

export interface SystemCheckResult {
	check: string;
	status: "infected" | "suspicious" | "clean" | "error";
	severity: "critical" | "high" | "medium" | "low";
	detail: string;
	campaign: string;
}

interface AggregatedIOCs {
	domains: Set<string>;
	ips: Set<string>;
	files: Set<string>;
	services: Set<string>;
	npmTokenDescriptions: Set<string>;
	persistencePaths: Set<string>;
	campaigns: Campaign[];
}

function aggregateIOCs(): AggregatedIOCs {
	const result: AggregatedIOCs = {
		domains: new Set(),
		ips: new Set(),
		files: new Set(),
		services: new Set(),
		npmTokenDescriptions: new Set(),
		persistencePaths: new Set(),
		campaigns: CAMPAIGNS,
	};

	for (const campaign of CAMPAIGNS) {
		for (const d of campaign.iocs.domains) result.domains.add(d);
		for (const ip of campaign.iocs.ips) result.ips.add(ip);
		for (const f of campaign.iocs.files) result.files.add(f);
		for (const s of campaign.iocs.services) result.services.add(s);
		for (const t of campaign.iocs.npmTokenDescriptions) result.npmTokenDescriptions.add(t);
		for (const p of campaign.iocs.persistencePaths) result.persistencePaths.add(p);
	}

	return result;
}

function execSafe(command: string, timeoutMs = 5000): string | null {
	try {
		const buf = execSync(command, { timeout: timeoutMs, encoding: "utf-8" });
		return buf;
	} catch {
		return null;
	}
}

export function runSystemChecks(_searchRoots: string[]): SystemCheckResult[] {
	const results: SystemCheckResult[] = [];
	const iocs = aggregateIOCs();
	const campaignNames = iocs.campaigns.map((c) => c.name);
	const campaignName = campaignNames.join(", ") || "unknown";

	// 1. Process scan
	const psOutput = execSafe("ps aux");
	if (psOutput !== null) {
		const foundServices: string[] = [];
		for (const svc of iocs.services) {
			if (psOutput.includes(svc)) {
				foundServices.push(svc);
			}
		}
		if (foundServices.length > 0) {
			results.push({
				check: "process-scan",
				status: "infected",
				severity: "critical",
				detail: `Suspicious processes found: ${foundServices.join(", ")}`,
				campaign: campaignName,
			});
		} else {
			results.push({
				check: "process-scan",
				status: "clean",
				severity: "low",
				detail: "No suspicious processes detected",
				campaign: campaignName,
			});
		}
	} else {
		results.push({
			check: "process-scan",
			status: "error",
			severity: "medium",
			detail: "Could not enumerate running processes",
			campaign: campaignName,
		});
	}

	// 2. Systemd user services
	const systemdDir = join(homedir(), ".config", "systemd", "user");
	if (existsSync(systemdDir)) {
		try {
			const files = readdirSync(systemdDir);
			const suspicious: string[] = [];
			for (const file of files) {
				if (!file.endsWith(".service")) continue;
				const content = readFileSync(join(systemdDir, file), "utf-8");
				for (const svc of iocs.services) {
					if (content.includes(svc)) {
						suspicious.push(file);
						break;
					}
				}
				for (const f of iocs.files) {
					if (content.includes(f)) {
						if (!suspicious.includes(file)) suspicious.push(file);
						break;
					}
				}
			}
			if (suspicious.length > 0) {
				results.push({
					check: "systemd-user-services",
					status: "suspicious",
					severity: "high",
					detail: `Suspicious user services: ${suspicious.join(", ")}`,
					campaign: campaignName,
				});
			} else {
				results.push({
					check: "systemd-user-services",
					status: "clean",
					severity: "low",
					detail: "No suspicious user systemd services detected",
					campaign: campaignName,
				});
			}
		} catch {
			results.push({
				check: "systemd-user-services",
				status: "error",
				severity: "medium",
				detail: "Could not read user systemd services",
				campaign: campaignName,
			});
		}
	} else {
		results.push({
			check: "systemd-user-services",
			status: "clean",
			severity: "low",
			detail: "No user systemd services directory found",
			campaign: campaignName,
		});
	}

	// 3. Crontab
	const crontabOutput = execSafe("crontab -l");
	if (crontabOutput !== null) {
		const hits: string[] = [];
		for (const domain of iocs.domains) {
			if (crontabOutput.includes(domain)) hits.push(domain);
		}
		for (const svc of iocs.services) {
			if (crontabOutput.includes(svc)) hits.push(svc);
		}
		for (const f of iocs.files) {
			if (crontabOutput.includes(f)) hits.push(f);
		}
		if (hits.length > 0) {
			results.push({
				check: "crontab",
				status: "suspicious",
				severity: "high",
				detail: `IOC strings in crontab: ${[...new Set(hits)].join(", ")}`,
				campaign: campaignName,
			});
		} else {
			results.push({
				check: "crontab",
				status: "clean",
				severity: "low",
				detail: "No suspicious entries in user crontab",
				campaign: campaignName,
			});
		}
	} else {
		results.push({
			check: "crontab",
			status: "error",
			severity: "medium",
			detail: "Could not read user crontab",
			campaign: campaignName,
		});
	}

	// 4. Persistence hooks (Claude Code, VS Code settings)
	const persistenceHits: string[] = [];
	const claudeSettings = join(homedir(), ".claude", "settings.json");
	const claudeLocal = join(homedir(), ".claude", "settings.local.json");
	const vscodeSettings = join(homedir(), ".config", "Code", "User", "settings.json");

	for (const path of [claudeSettings, claudeLocal, vscodeSettings]) {
		if (!existsSync(path)) continue;
		try {
			const content = readFileSync(path, "utf-8");
			for (const domain of iocs.domains) {
				if (content.includes(domain)) persistenceHits.push(`${path} (domain: ${domain})`);
			}
			for (const f of iocs.files) {
				if (content.includes(f)) persistenceHits.push(`${path} (file: ${f})`);
			}
		} catch {
			// ignore read errors
		}
	}

	if (persistenceHits.length > 0) {
		results.push({
			check: "persistence-hooks",
			status: "infected",
			severity: "critical",
			detail: `Persistence indicators in settings: ${persistenceHits.join("; ")}`,
			campaign: campaignName,
		});
	} else {
		results.push({
			check: "persistence-hooks",
			status: "clean",
			severity: "low",
			detail: "No persistence hooks detected in editor settings",
			campaign: campaignName,
		});
	}

	// 5. npm tokens
	const npmTokenOutput = execSafe("npm token list --json", 10000);
	if (npmTokenOutput !== null) {
		try {
			const tokens = JSON.parse(npmTokenOutput) as Array<Record<string, unknown>>;
			const suspiciousTokens: string[] = [];
			for (const token of tokens) {
				const desc = String(token.description ?? token.token ?? "");
				for (const maliciousDesc of iocs.npmTokenDescriptions) {
					if (desc.includes(maliciousDesc)) {
						suspiciousTokens.push(desc);
					}
				}
			}
			if (suspiciousTokens.length > 0) {
				results.push({
					check: "npm-tokens",
					status: "infected",
					severity: "critical",
					detail: `Suspicious npm token descriptions: ${suspiciousTokens.join(", ")}`,
					campaign: campaignName,
				});
			} else {
				results.push({
					check: "npm-tokens",
					status: "clean",
					severity: "low",
					detail: "No suspicious npm tokens found",
					campaign: campaignName,
				});
			}
		} catch {
			results.push({
				check: "npm-tokens",
				status: "error",
				severity: "medium",
				detail: "Could not parse npm token list output",
				campaign: campaignName,
			});
		}
	} else {
		results.push({
			check: "npm-tokens",
			status: "error",
			severity: "medium",
			detail: "Could not run npm token list",
			campaign: campaignName,
		});
	}

	// 6. Malicious files
	const commonPaths = [
		homedir(),
		join(homedir(), ".config"),
		join(homedir(), ".local"),
		"/tmp",
		"/var/tmp",
		process.cwd(),
	];
	const foundFiles: string[] = [];
	for (const iocFile of iocs.files) {
		// Check absolute paths directly
		if (iocFile.startsWith("/") && existsSync(iocFile)) {
			foundFiles.push(iocFile);
			continue;
		}
		// Check in common locations
		for (const base of commonPaths) {
			const full = join(base, iocFile);
			if (existsSync(full)) {
				foundFiles.push(full);
				break;
			}
		}
	}
	if (foundFiles.length > 0) {
		results.push({
			check: "malicious-files",
			status: "infected",
			severity: "critical",
			detail: `Known malicious files found: ${foundFiles.join(", ")}`,
			campaign: campaignName,
		});
	} else {
		results.push({
			check: "malicious-files",
			status: "clean",
			severity: "low",
			detail: "No known malicious files detected in common locations",
			campaign: campaignName,
		});
	}

	// 7. Network connections
	const ssOutput = execSafe("ss -tn");
	const networkHits: string[] = [];
	if (ssOutput !== null) {
		for (const ip of iocs.ips) {
			if (ssOutput.includes(ip)) networkHits.push(ip);
		}
	}

	const hostsFile = "/etc/hosts";
	if (existsSync(hostsFile)) {
		try {
			const hostsContent = readFileSync(hostsFile, "utf-8");
			for (const domain of iocs.domains) {
				if (hostsContent.includes(domain)) networkHits.push(`hosts:${domain}`);
			}
		} catch {
			// ignore
		}
	}

	if (networkHits.length > 0) {
		results.push({
			check: "network-connections",
			status: "suspicious",
			severity: "high",
			detail: `Network IOC hits: ${networkHits.join(", ")}`,
			campaign: campaignName,
		});
	} else {
		results.push({
			check: "network-connections",
			status: "clean",
			severity: "low",
			detail: "No suspicious network connections or hosts entries",
			campaign: campaignName,
		});
	}

	return results;
}
