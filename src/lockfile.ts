/**
 * Lockfile parsers for npm, pnpm, bun, and Python package managers.
 */

import { readFile } from "node:fs/promises";
import { basename } from "node:path";

export interface LockfileResult {
	path: string;
	type: "package-lock" | "bun" | "pnpm" | "requirements" | "pipfile" | "poetry";
	packages: Map<string, string>;
}

export async function parseLockfile(filePath: string): Promise<LockfileResult | null> {
	const name = basename(filePath);

	try {
		const content = await readFile(filePath, "utf-8");

		switch (name) {
			case "package-lock.json":
				return parsePackageLock(filePath, content);
			case "bun.lock":
				return parseBunLock(filePath, content);
			case "pnpm-lock.yaml":
				return parsePnpmLock(filePath, content);
			case "requirements.txt":
				return parseRequirements(filePath, content);
			case "Pipfile.lock":
				return parsePipfileLock(filePath, content);
			case "poetry.lock":
				return parsePoetryLock(filePath, content);
			default:
				return null;
		}
	} catch {
		return null;
	}
}

function parsePackageLock(path: string, content: string): LockfileResult | null {
	try {
		const data = JSON.parse(content) as Record<string, unknown>;
		const packages = new Map<string, string>();

		if (data.packages && typeof data.packages === "object") {
			// v2 / v3
			for (const [key, val] of Object.entries(data.packages)) {
				if (!val || typeof val !== "object") continue;
				const pkg = val as Record<string, unknown>;
				if (typeof pkg.version === "string") {
					const name = key.replace(/^node_modules\//, "");
					if (name) {
						packages.set(name, pkg.version);
					}
				}
			}
		} else if (data.dependencies && typeof data.dependencies === "object") {
			// v1
			walkPackageLockV1(data.dependencies as Record<string, unknown>, packages);
		}

		return { path, type: "package-lock", packages };
	} catch {
		return null;
	}
}

function walkPackageLockV1(deps: Record<string, unknown>, out: Map<string, string>): void {
	for (const [name, val] of Object.entries(deps)) {
		if (!val || typeof val !== "object") continue;
		const pkg = val as Record<string, unknown>;
		if (typeof pkg.version === "string") {
			out.set(name, pkg.version);
		}
		if (pkg.dependencies && typeof pkg.dependencies === "object") {
			walkPackageLockV1(pkg.dependencies as Record<string, unknown>, out);
		}
	}
}

function parseBunLock(path: string, content: string): LockfileResult | null {
	const packages = new Map<string, string>();
	// Match lines like: "pkg": ["pkg@version",
	const re = /"([^"]+)":\s*\["([^"@]+@([^"]+))"/g;
	let m: RegExpExecArray | null = re.exec(content);
	while (m !== null) {
		const name = m[1];
		const version = m[3];
		if (name && version) {
			packages.set(name, version);
		}
		m = re.exec(content);
	}
	return { path, type: "bun", packages };
}

function parsePnpmLock(path: string, content: string): LockfileResult | null {
	const packages = new Map<string, string>();
	// Extract packages section
	const lines = content.split("\n");
	let inPackages = false;

	for (const line of lines) {
		if (line.trim() === "packages:") {
			inPackages = true;
			continue;
		}
		if (inPackages) {
			// Stop at next top-level section (no indent or different section)
			if (line.match(/^[a-zA-Z_][a-zA-Z0-9_]*:/) && !line.startsWith(" ")) {
				if (line.trim() !== "packages:") break;
			}
			// Match /pkg-name@version: or /pkg-name@version(peer): lines
			const m = line.match(/\/(?:@[^/]+\/)?([^/@]+)@([^:]+):/);
			if (m) {
				const name = m[1];
				const version = m[2];
				// For scoped packages, reconstruct the name
				const scopedM = line.match(/\/(@[^/]+\/[^/@]+)@([^:]+):/);
				if (scopedM) {
					packages.set(scopedM[1], scopedM[2]);
				} else if (name && version) {
					packages.set(name, version);
				}
			}
		}
	}

	return { path, type: "pnpm", packages };
}

function parseRequirements(path: string, content: string): LockfileResult | null {
	const packages = new Map<string, string>();
	const lines = content.split("\n");

	for (const line of lines) {
		const trimmed = line.trim();
		if (trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
		const m = trimmed.match(/^([a-zA-Z0-9_.-]+)==(.+)$/);
		if (m) {
			packages.set(m[1].toLowerCase(), m[2]);
		}
	}

	return { path, type: "requirements", packages };
}

function parsePipfileLock(path: string, content: string): LockfileResult | null {
	try {
		const data = JSON.parse(content) as Record<string, unknown>;
		const packages = new Map<string, string>();

		for (const section of ["default", "develop"]) {
			const sec = data[section];
			if (!sec || typeof sec !== "object") continue;
			for (const [name, val] of Object.entries(sec)) {
				if (!val || typeof val !== "object") continue;
				const pkg = val as Record<string, unknown>;
				let version = pkg.version;
				if (typeof version === "string" && version.startsWith("==")) {
					version = version.slice(2);
				}
				if (typeof version === "string") {
					packages.set(name.toLowerCase(), version);
				}
			}
		}

		return { path, type: "pipfile", packages };
	} catch {
		return null;
	}
}

function parsePoetryLock(path: string, content: string): LockfileResult | null {
	const packages = new Map<string, string>();
	const blocks = content.split("[[package]]");

	for (const block of blocks.slice(1)) {
		const nameM = block.match(/name\s*=\s*"([^"]+)"/);
		const versionM = block.match(/version\s*=\s*"([^"]+)"/);
		if (nameM && versionM) {
			packages.set(nameM[1].toLowerCase(), versionM[1]);
		}
	}

	return { path, type: "poetry", packages };
}
