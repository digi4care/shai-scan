import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const FIXTURES = join(ROOT, "test", "fixtures");

// All CLI tests run the compiled dist/cli.js, so they require a prior build.
function run(args: string): { stdout: string; stderr: string; exitCode: number } {
	try {
		const stdout = execSync(`node ${CLI} ${args}`, { encoding: "utf-8", stdio: "pipe" });
		return { stdout, stderr: "", exitCode: 0 };
	} catch (err: unknown) {
		const e = err as { stdout?: string; stderr?: string; status?: number };
		return { stdout: e.stdout ?? "", stderr: e.stderr ?? "", exitCode: e.status ?? 1 };
	}
}

describe("cli", () => {
	describe("--version", () => {
		it("outputs version matching package.json", () => {
			const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf-8"));
			const { stdout, exitCode } = run("--version");
			assert.equal(exitCode, 0);
			assert.equal(stdout.trim(), pkg.version);
		});
	});

	describe("--help", () => {
		it("outputs usage information", () => {
			const { stdout, exitCode } = run("--help");
			assert.equal(exitCode, 0);
			assert.ok(stdout.includes("shai-scan"));
			assert.ok(stdout.includes("Options"));
		});
	});

	describe("exit codes", () => {
		it("exits 1 when findings are found", () => {
			const { exitCode } = run(`--lockfiles-only ${join(FIXTURES, "compromised-project")}`);
			assert.equal(exitCode, 1);
		});

		it("exits 0 when no findings", () => {
			const { exitCode } = run(`--lockfiles-only ${join(FIXTURES, "clean-project")}`);
			assert.equal(exitCode, 0);
		});
	});

	describe("--json", () => {
		it("produces valid JSON with findings for compromised project", () => {
			const { stdout, exitCode } = run(`--json --lockfiles-only ${join(FIXTURES, "compromised-project")}`);
			assert.equal(exitCode, 1);

			const data = JSON.parse(stdout);
			assert.ok(typeof data.version === "string");
			assert.ok(Array.isArray(data.findings.lockfile));
			assert.equal(data.findings.lockfile.length, 11);
			assert.equal(data.summary.compromisedPackages, 11);
			assert.equal(data.exitCode, 1);
		});

		it("produces valid JSON with no findings for clean project", () => {
			const { stdout, exitCode } = run(`--json --lockfiles-only ${join(FIXTURES, "clean-project")}`);
			assert.equal(exitCode, 0);

			const data = JSON.parse(stdout);
			assert.equal(data.findings.lockfile.length, 0);
			assert.equal(data.summary.compromisedPackages, 0);
			assert.equal(data.exitCode, 0);
		});
	});

	describe("--sarif", () => {
		it("produces valid SARIF structure", () => {
			const { stdout, exitCode } = run(`--sarif --lockfiles-only ${join(FIXTURES, "compromised-project")}`);
			assert.equal(exitCode, 1);

			const sarif = JSON.parse(stdout);
			assert.equal(
				sarif.$schema,
				"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			);
			assert.equal(sarif.version, "2.1.0");
			assert.ok(Array.isArray(sarif.runs));
			assert.ok(sarif.runs.length > 0);
			assert.ok(Array.isArray(sarif.runs[0].results));
			assert.equal(sarif.runs[0].results.length, 11);
		});
	});

	describe("--text (default)", () => {
		it("outputs human-readable text for findings", () => {
			const { stdout, exitCode } = run(`--text --lockfiles-only ${join(FIXTURES, "compromised-project")}`);
			assert.equal(exitCode, 1);
			assert.ok(stdout.includes("[CRITICAL]"));
			assert.ok(stdout.includes("@tanstack/react-router"));
			assert.ok(stdout.includes("COMPROMISE DETECTED"));
		});

		it("outputs clean message for clean project", () => {
			const { stdout, exitCode } = run(`--text --lockfiles-only ${join(FIXTURES, "clean-project")}`);
			assert.equal(exitCode, 0);
			assert.ok(stdout.toLowerCase().includes("clean") || stdout.toLowerCase().includes("no compromis"));
		});
	});
});
