/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";

const solution = path.join(__dirname, "fixtures", "project-references-solution");

function withConfig(config: unknown, check: (directory: string) => void): void {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-references-"));
    try {
        fs.writeFileSync(path.join(directory, "tsconfig.json"), JSON.stringify(config));
        fs.writeFileSync(path.join(directory, "entry.ts"), "export const value = 1;\n");
        check(directory);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
}

describe("reference-only TypeScript solutions", () => {
    it("rejects a reference-only config rather than returning an empty program", () => {
        expect(() => parseProject(solution)).toThrow(/project references but no input files/);
        expect(() => parseProject(solution)).toThrow(path.join(solution, "tsconfig.json"));
    });

    it.each([false, true])("rejects empty solution analysis with requireTypes=%s", async (requireTypes) => {
        await expect(analyze({ projectDir: solution, requireTypes })).rejects.toThrow(/separate --project arguments/);
    });

    it("finds the unsafe flow when its referenced project is scanned directly", async () => {
        const projectDir = path.join(solution, "app");
        const parsed = parseProject(projectDir);
        expect(parsed.program.getSyntacticDiagnostics()).toEqual([]);
        expect(parsed.program.getSemanticDiagnostics()).toEqual([]);
        const result = await analyze({ projectDir, requireTypes: true });
        expect(result.typeEnvironmentWarning).toBeUndefined();
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.name).toBe("exec");
        expect(result.entryPointCount).toBeGreaterThan(0);
    });

    it.each([{ files: [] }, { files: [], references: [] }])("allows an intentionally empty leaf: %j", (config) => {
        withConfig(config, (directory) => {
            expect(parseProject(directory).sourceFiles).toEqual([]);
        });
    });

    it("does not confuse explicit exclusions with a reference-only config", () => {
        withConfig({ files: ["entry.ts"], references: [{ path: "./dependency" }] }, (directory) => {
            expect(parseProject(directory, ["entry.ts"]).sourceFiles).toEqual([]);
        });
    });

    it("still analyzes a referencing config's own input files", () => {
        withConfig({ files: ["entry.ts"], references: [{ path: "./dependency" }] }, (directory) => {
            expect(parseProject(directory).sourceFiles.map((file) => path.basename(file.fileName))).toEqual([
                "entry.ts",
            ]);
        });
    });
});
