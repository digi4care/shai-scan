import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildLookup, CAMPAIGNS } from "../src/db.js";

describe("db", () => {
	describe("CAMPAIGNS", () => {
		it("has at least one campaign", () => {
			assert.ok(CAMPAIGNS.length > 0);
		});

		for (const campaign of CAMPAIGNS) {
			describe(campaign.name, () => {
				it("has required string fields", () => {
					assert.ok(typeof campaign.id === "string" && campaign.id.length > 0);
					assert.ok(typeof campaign.name === "string" && campaign.name.length > 0);
					assert.ok(typeof campaign.date === "string" && campaign.date.length > 0);
					assert.ok(typeof campaign.attribution === "string" && campaign.attribution.length > 0);
					assert.ok(typeof campaign.severity === "string" && campaign.severity.length > 0);
					assert.ok(typeof campaign.description === "string" && campaign.description.length > 0);
				});

				it("has severity in valid set", () => {
					assert.ok(["critical", "high", "medium"].includes(campaign.severity));
				});

				it("has at least one package", () => {
					assert.ok(campaign.packages.length > 0);
				});

				it("packages have required fields", () => {
					for (const pkg of campaign.packages) {
						assert.ok(typeof pkg.name === "string" && pkg.name.length > 0);
						assert.ok(Array.isArray(pkg.versions) && pkg.versions.length > 0);
						assert.ok(["npm", "pypi"].includes(pkg.ecosystem));
					}
				});

				it("referenceUrls is an array", () => {
					assert.ok(Array.isArray(campaign.referenceUrls));
				});
			});
		}
	});

	describe("buildLookup()", () => {
		it("returns a Map keyed by package name", () => {
			const lookup = buildLookup();
			assert.ok(lookup instanceof Map);
			assert.ok(lookup.size > 0);
		});

		it("maps known compromised package to entry with versions", () => {
			const lookup = buildLookup();
			const entries = lookup.get("@tanstack/react-router");
			assert.ok(entries, "should find @tanstack/react-router");
			assert.ok(entries.length > 0);
			assert.ok(entries[0].compromisedVersions instanceof Set);
			assert.ok(entries[0].compromisedVersions.has("1.169.8"));
		});

		it("returns undefined for unknown package", () => {
			const lookup = buildLookup();
			assert.equal(lookup.get("nonexistent-package-xyz"), undefined);
		});

		it("clean version is not in compromised versions", () => {
			const lookup = buildLookup();
			const entries = lookup.get("@tanstack/react-router");
			assert.ok(entries);
			assert.ok(!entries[0].compromisedVersions.has("1.163.2"));
		});
	});
});
