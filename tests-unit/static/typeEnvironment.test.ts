/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyzeFixture } from "./testUtils";
import { parseProject } from "../../src/static/parser";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

describe("type environment check", () => {
    it("resolves type packages from ancestor node_modules", () => {
        const temp = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-type-package-"));
        const projectDir = path.join(temp, "project");
        const nodeModulesTypes = path.join(temp, "node_modules", "@types", "test-package");
        fs.mkdirSync(projectDir);
        fs.mkdirSync(nodeModulesTypes, { recursive: true });
        fs.writeFileSync(
            path.join(nodeModulesTypes, "index.d.ts"),
            "declare global { const testGlobal: string; }\nexport {};\n",
        );
        fs.writeFileSync(
            path.join(nodeModulesTypes, "package.json"),
            JSON.stringify({ name: "@types/test-package", version: "1.0.0", types: "index.d.ts" }),
        );
        fs.writeFileSync(
            path.join(projectDir, "tsconfig.json"),
            JSON.stringify({
                compilerOptions: { moduleResolution: "bundler", module: "esnext", types: ["test-package"] },
                include: ["*.ts"],
            }),
        );
        fs.writeFileSync(path.join(projectDir, "extension.ts"), "testGlobal;\n");
        try {
            const diagnostics = parseProject(projectDir).program.getOptionsDiagnostics();
            expect(diagnostics.filter(({ code }) => code === 2688)).toEqual([]);
        } finally {
            fs.rmSync(temp, { recursive: true, force: true });
        }
    });

    it("warns when Node built-ins and configured type libraries have no declarations", async () => {
        const result = await analyzeFixture("untyped-node-module-rce");
        expect(result.typeEnvironmentWarning).toContain("child_process ×1");
        expect(result.typeEnvironmentWarning).toContain("prophecy-missing-types");
        expect(result.findings).toHaveLength(1);
    });

    it("fails the scan when types are required", async () => {
        await expect(analyzeFixture("untyped-node-module-rce", { requireTypes: true })).rejects.toThrow(
            /Missing type declarations .*child_process ×1/,
        );
    });

    it("accepts a project whose declarations resolve", async () => {
        const result = await analyzeFixture("workspace-config-object-rce", { requireTypes: true });
        expect(result.typeEnvironmentWarning).toBeUndefined();
        expect(result.findings).toHaveLength(1);
    });
});
