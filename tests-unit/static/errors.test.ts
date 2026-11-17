/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { analyzeFixture } from "./testUtils";

describe("E2E: Error handling edge cases", () => {
    it("nonexistent projectDir: rejects with a descriptive error", async () => {
        await expect(
            analyze({
                projectDir: "/nonexistent/path/that/does/not/exist",
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "text",
            }),
        ).rejects.toThrow("Project directory does not exist");
    });

    it("malformed tsconfig.json: rejects with a configuration diagnostic", async () => {
        await expect(analyzeFixture("malformed-tsconfig")).rejects.toThrow("failed to parse tsconfig.json");
    });

    it("TypeScript syntax errors: reports syntax errors with locations", async () => {
        const result = await analyzeFixture("syntax-errors");
        expect(result).toBeDefined();
        expect(Array.isArray(result.findings)).toBe(true);
        expect(result.syntaxErrors.length).toBeGreaterThan(0);
        expect(result.syntaxErrors[0]).toMatch(/extension\.ts:\d+:\d+:/);
    });

    it("zero entry points: returns 0 findings gracefully", async () => {
        const result = await analyzeFixture("zero-entry-points");
        expect(result).toBeDefined();
        expect(result.findings.length).toBe(0);
    });

    it("empty project directory: returns 0 findings with no .ts files", async () => {
        const result = await analyzeFixture("empty-project");
        expect(result).toBeDefined();
        expect(result.findings.length).toBe(0);
        expect(result.warnings.join("\n")).toContain("No inputs were found");
    });
});
