/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyze, AnalyzerOptions } from "../../src/static/analyzer";
import { analyzeDiffScreening } from "../../src/static/diff";
import { parseProject, ProjectConfigurationError } from "../../src/static/parser";

let directory: string;

beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-project-input-"));
    fs.writeFileSync(path.join(directory, "main.ts"), "export function main() {}\n");
});

afterEach(() => {
    fs.rmSync(directory, { recursive: true, force: true });
});

describe("project input validation", () => {
    it.each([
        [{ extends: "./missing.json" }, "Cannot read file"],
        [{ files: ["missing.ts"] }, "not found"],
        [{ files: "main.ts" }, "Compiler option 'files'"],
        [{ include: [42] }, "Compiler option 'include'"],
        [{ exclude: 42 }, "Compiler option 'exclude'"],
        [{ include: ["**/../*.ts"] }, "File specification"],
    ])("rejects input-resolution errors in %j", (config, message) => {
        fs.writeFileSync(path.join(directory, "tsconfig.json"), JSON.stringify(config));
        expect(() => parseProject(directory)).toThrow(message as string);
        expect(() => parseProject(directory)).toThrow(ProjectConfigurationError);
    });

    it("rejects malformed configs found in ancestors", () => {
        const sourceDirectory = path.join(directory, "src");
        fs.mkdirSync(sourceDirectory);
        fs.writeFileSync(path.join(directory, "tsconfig.json"), "{ invalid json !!!");
        expect(() => parseProject(sourceDirectory)).toThrow("failed to parse tsconfig.json");
    });

    it("rejects malformed and circular extended configs", () => {
        fs.writeFileSync(path.join(directory, "tsconfig.json"), '{"extends":"./base.json"}');
        fs.writeFileSync(path.join(directory, "base.json"), "{ invalid json !!!");
        expect(() => parseProject(directory)).toThrow("base.json");
        fs.writeFileSync(path.join(directory, "base.json"), '{"extends":"./tsconfig.json"}');
        expect(() => parseProject(directory)).toThrow("Circularity");
    });

    it("tolerates unrelated compiler-option diagnostics in extended configs", () => {
        fs.writeFileSync(path.join(directory, "tsconfig.json"), '{"extends":"./base.json"}');
        fs.writeFileSync(
            path.join(directory, "base.json"),
            '{"compilerOptions":{"definitelyUnknownCompilerOption":true},"include":["*.ts"]}',
        );
        expect(parseProject(directory).sourceFiles.map((source) => path.basename(source.fileName))).toEqual([
            "main.ts",
        ]);
    });

    it("retains a diagnostic when include patterns select no input files", async () => {
        fs.writeFileSync(path.join(directory, "tsconfig.json"), '{"include":["wrong/*.ts"]}');
        const result = await analyze({ projectDir: directory, outputFormat: "json", requireTypes: true });
        expect(result.findings).toEqual([]);
        expect(result.warnings.join("\n")).toContain("No inputs were found");
        expect(result.warnings.join("\n")).toContain("wrong/*.ts");
    });

    it("allows an explicitly empty project while retaining its diagnostic", () => {
        fs.writeFileSync(path.join(directory, "tsconfig.json"), '{"files":[]}');
        const parsed = parseProject(directory);
        expect(parsed.sourceFiles).toEqual([]);
        expect(parsed.warnings?.join("\n")).toContain("'files' list");
    });
});

describe("analysis option validation", () => {
    const invalidOptions: Array<Partial<AnalyzerOptions>> = [
        { shardCount: 0 },
        { shardCount: -1 },
        { shardCount: 1.5 },
        { shardCount: NaN },
        { shardCount: Infinity },
        { shardIndex: -1 },
        { shardIndex: 0.5, shardCount: 2 },
        { shardIndex: 2, shardCount: 2 },
        { shardIndex: NaN },
        { maxDepth: -1 },
        { maxDepth: 1.5 },
        { maxDepth: NaN },
        { maxDepth: Infinity },
    ];

    it.each(invalidOptions)("rejects invalid API options %j before reading input", async (options) => {
        await expect(analyze({ projectDir: "/missing-project", ...options })).rejects.toThrow(/--(shard|max-depth)/);
    });

    it("validates depth in patch mode even when the patch contains no TypeScript", async () => {
        await expect(analyzeDiffScreening({ maxDepth: NaN })).rejects.toThrow("--max-depth");
    });

    it("accepts zero depth and a valid empty shard", async () => {
        const result = await analyze({
            source: "export function main() {}",
            maxDepth: 0,
            shardCount: 2,
            shardIndex: 1,
        });
        expect(result.entryPointCount).toBe(0);
        expect(result.findings).toEqual([]);
    });
});
