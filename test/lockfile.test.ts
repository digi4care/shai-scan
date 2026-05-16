import assert from "node:assert/strict";
import { join } from "node:path";
import { describe, it } from "node:test";
import { parseLockfile } from "../src/lockfile.js";

// import.meta.dirname is dist-test/test/ when compiled, test/ when run by bun
const ROOT = join(import.meta.dirname, "..", "..");
const FIXTURES = join(ROOT, "test", "fixtures");

describe("lockfile", () => {
	describe("package-lock.json", () => {
		it("parses v3 lockfile with compromised packages", async () => {
			const result = await parseLockfile(join(FIXTURES, "compromised-project", "package-lock.json"));
			assert.ok(result);
			assert.equal(result.type, "package-lock");

			assert.ok(result.packages.has("@tanstack/react-router"));
			assert.equal(result.packages.get("@tanstack/react-router"), "1.169.8");

			assert.ok(result.packages.has("@mistralai/mistralai"));
			assert.equal(result.packages.get("@mistralai/mistralai"), "2.2.4");

			assert.ok(result.packages.has("@opensearch-project/opensearch"));
			assert.equal(result.packages.get("@opensearch-project/opensearch"), "3.8.0");

			assert.ok(result.packages.has("safe-action"));
			assert.equal(result.packages.get("safe-action"), "0.8.4");

			// Clean package present but not compromised
			assert.ok(result.packages.has("react"));
			assert.equal(result.packages.get("react"), "19.1.0");
		});

		it("parses clean lockfile", async () => {
			const result = await parseLockfile(join(FIXTURES, "clean-project", "package-lock.json"));
			assert.ok(result);
			assert.equal(result.type, "package-lock");
			assert.equal(result.packages.get("@tanstack/react-router"), "1.163.2");
			assert.equal(result.packages.get("@mistralai/mistralai"), "1.14.1");
		});
	});

	describe("pnpm-lock.yaml", () => {
		it("parses pnpm lockfile with scoped packages", async () => {
			const result = await parseLockfile(join(FIXTURES, "compromised-project", "pnpm-lock.yaml"));
			assert.ok(result);
			assert.equal(result.type, "pnpm");

			assert.ok(result.packages.has("@uipath/robot"));
			assert.equal(result.packages.get("@uipath/robot"), "1.3.4");

			assert.ok(result.packages.has("@uipath/cli"));
			assert.equal(result.packages.get("@uipath/cli"), "1.0.1");

			// Clean package
			assert.ok(result.packages.has("lodash"));
			assert.equal(result.packages.get("lodash"), "4.17.21");
		});
	});

	describe("requirements.txt", () => {
		it("parses pip requirements with == versions", async () => {
			const result = await parseLockfile(join(FIXTURES, "compromised-project", "requirements.txt"));
			assert.ok(result);
			assert.equal(result.type, "requirements");

			assert.ok(result.packages.has("mistralai"));
			assert.equal(result.packages.get("mistralai"), "2.4.6");

			assert.ok(result.packages.has("guardrails-ai"));
			assert.equal(result.packages.get("guardrails-ai"), "0.10.1");

			// Clean packages
			assert.ok(result.packages.has("requests"));
			assert.ok(result.packages.has("flask"));
		});
	});

	describe("bun.lock", () => {
		it("parses JSON-format bun.lock", async () => {
			const result = await parseLockfile(join(FIXTURES, "compromised-project", "bun.lock"));
			assert.ok(result);
			assert.equal(result.type, "bun");

			assert.ok(result.packages.has("@squawk/mcp"));
			assert.equal(result.packages.get("@squawk/mcp"), "0.9.4");

			assert.ok(result.packages.has("@squawk/weather"));
			assert.equal(result.packages.get("@squawk/weather"), "0.5.9");

			assert.ok(result.packages.has("@mistralai/mistralai"));
			assert.equal(result.packages.get("@mistralai/mistralai"), "2.2.3");

			assert.ok(result.packages.has("react"));
			assert.equal(result.packages.get("react"), "19.1.0");
		});
	});

	describe("edge cases", () => {
		it("returns null for nonexistent file", async () => {
			const result = await parseLockfile("/nonexistent/path/package-lock.json");
			assert.equal(result, null);
		});

		it("returns null for unrecognized filename", async () => {
			const result = await parseLockfile(join(FIXTURES, "compromised-project", "requirements.txt.bak"));
			assert.equal(result, null);
		});
	});
});
