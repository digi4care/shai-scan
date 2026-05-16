import assert from "node:assert/strict";
import { join } from "node:path";
import { describe, it } from "node:test";
import { scan } from "../src/scanner.js";

// import.meta.dirname is dist-test/test/ when compiled, test/ when run by bun
const ROOT = join(import.meta.dirname, "..", "..");
const FIXTURES = join(ROOT, "test", "fixtures");

// Expected compromised findings from fixture lockfiles:
// package-lock.json: @tanstack/react-router 1.169.8, @mistralai/mistralai 2.2.4,
//   @opensearch-project/opensearch 3.8.0, safe-action 0.8.4
// bun.lock: @squawk/mcp 0.9.4, @squawk/weather 0.5.9, @mistralai/mistralai 2.2.3
// pnpm-lock.yaml: @uipath/robot 1.3.4, @uipath/cli 1.0.1
// requirements.txt: mistralai 2.4.6, guardrails-ai 0.10.1
// Total: 11 lockfile findings

describe("scanner", () => {
	describe("compromised project", () => {
		it("finds 11 compromised packages", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			assert.equal(result.lockfileFindings.length, 11);
		});

		it("scans all 4 lockfiles", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			assert.equal(result.lockfilesScanned, 4);
		});

		it("findings have correct structure", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			for (const f of result.lockfileFindings) {
				assert.ok(typeof f.lockfile === "string" && f.lockfile.length > 0);
				assert.ok(typeof f.packageName === "string" && f.packageName.length > 0);
				assert.ok(typeof f.version === "string" && f.version.length > 0);
				assert.ok(typeof f.severity === "string" && f.severity.length > 0);
				assert.ok(typeof f.campaign === "object");
				assert.ok(typeof f.campaign.id === "string");
			}
		});

		it("detects package-lock.json compromises", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			const pkgLockFindings = result.lockfileFindings.filter((f) => f.lockfile === "package-lock.json");
			assert.equal(pkgLockFindings.length, 4);

			const names = new Set(pkgLockFindings.map((f) => f.packageName));
			assert.ok(names.has("@tanstack/react-router"));
			assert.ok(names.has("@mistralai/mistralai"));
			assert.ok(names.has("@opensearch-project/opensearch"));
			assert.ok(names.has("safe-action"));
		});

		it("detects pnpm-lock.yaml compromises", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			const pnpmFindings = result.lockfileFindings.filter((f) => f.lockfile === "pnpm-lock.yaml");
			assert.equal(pnpmFindings.length, 2);

			const names = new Set(pnpmFindings.map((f) => f.packageName));
			assert.ok(names.has("@uipath/robot"));
			assert.ok(names.has("@uipath/cli"));
		});

		it("detects requirements.txt compromises", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			const reqFindings = result.lockfileFindings.filter((f) => f.lockfile === "requirements.txt");
			assert.equal(reqFindings.length, 2);

			const names = new Set(reqFindings.map((f) => f.packageName));
			assert.ok(names.has("mistralai"));
			assert.ok(names.has("guardrails-ai"));
		});

		it("detects bun.lock compromises", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			const bunFindings = result.lockfileFindings.filter((f) => f.lockfile === "bun.lock");
			assert.equal(bunFindings.length, 3);

			const names = new Set(bunFindings.map((f) => f.packageName));
			assert.ok(names.has("@squawk/mcp"));
			assert.ok(names.has("@squawk/weather"));
			assert.ok(names.has("@mistralai/mistralai"));
		});

		it("does not flag clean versions", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			const names = result.lockfileFindings.map((f) => f.packageName);
			assert.ok(!names.includes("react"), "react is a clean dependency");
			assert.ok(!names.includes("lodash"), "lodash is a clean dependency");
		});
	});

	describe("clean project", () => {
		it("finds zero compromised packages", async () => {
			const result = await scan(join(FIXTURES, "clean-project"), { lockfilesOnly: true });
			assert.equal(result.lockfileFindings.length, 0);
		});

		it("still scans lockfiles", async () => {
			const result = await scan(join(FIXTURES, "clean-project"), { lockfilesOnly: true });
			assert.equal(result.lockfilesScanned, 1);
		});
	});

	describe("options", () => {
		it("lockfilesOnly skips system checks", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { lockfilesOnly: true });
			assert.equal(result.systemFindings.length, 0);
		});

		it("systemOnly skips lockfile scanning", async () => {
			const result = await scan(join(FIXTURES, "compromised-project"), { systemOnly: true });
			assert.equal(result.lockfileFindings.length, 0);
			assert.equal(result.lockfilesScanned, 0);
		});
	});
});
