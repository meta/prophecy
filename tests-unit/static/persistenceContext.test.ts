/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { findingReporting } from "../../src/static/findingUtils";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { TaintSpec } from "../../src/static/spec/types";

async function scan(body: string, spec?: TaintSpec) {
    const result = await analyze({
        source: `import * as fs from 'node:fs'; import * as vscode from 'vscode';
            export function activate() { vscode.window.registerUriHandler({
                handleUri(uri: vscode.Uri) { ${body} }
            }); }`,
        fileName: path.join(__dirname, "persistence-context-input.ts"),
        spec,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("Persistence destination and consumer context", () => {
    it.each(["/tmp/cache.json", ".vscode/tasks.json", "/tmp/authorized_keys"])(
        "does not infer privileged consumption from filename %s",
        async (destination) => {
            const findings = await scan(`fs.writeFileSync(${JSON.stringify(destination)}, uri.query);`);
            expect(findings.map((f) => [f.sink.name, f.sink.categories, f.sink.severity])).toEqual([
                ["writeFileSync", ["file_integrity"], "low"],
            ]);
            expect(findingReporting(findings[0].sink).kind).toBe("persistence_trace");
        },
    );

    it("retains unknown destination content and independently reports path control", async () => {
        const findings = await scan(`fs.writeFileSync(uri.path, uri.query);`);
        expect(findings.map((f) => [f.sink.name, f.sink.categories, f.sink.severity])).toEqual([
            ["writeFileSync_path", ["file_write"], "high"],
            ["writeFileSync", ["file_integrity"], "low"],
        ]);
    });

    it.each(["appendFile", "appendFileSync"])("applies the same distinction to fs.%s", async (method) => {
        const callback = method === "appendFile" ? ", () => {}" : "";
        const findings = await scan(`fs.${method}(uri.path, uri.query${callback});`);
        expect(findings.map((f) => [f.sink.name, f.sink.categories, f.sink.severity])).toEqual([
            [`${method}_path`, ["file_write"], "high"],
            [method, ["file_integrity"], "low"],
        ]);
    });

    it("preserves stream path selection and its file-descriptor control", async () => {
        const findings = await scan(`fs.createWriteStream(uri.path); fs.createWriteStream(uri.path, {fd: 0});`);
        expect(findings.map((f) => [f.sink.name, f.sink.categories])).toEqual([
            ["createWriteStream_path", ["file_write"]],
        ]);
    });

    it("classifies VS Code content separately from VS Code path control", async () => {
        const findings = await scan(`vscode.workspace.fs.writeFile(uri, new TextEncoder().encode(uri.query));`);
        expect(findings.map((f) => [f.sink.name, f.sink.categories, f.sink.severity])).toEqual([
            ["vscode_writeFile", ["file_integrity"], "low"],
            ["vscode_writeFile_path", ["file_write"], "high"],
        ]);
    });

    it("does not infer persistence or path effects from local write lookalikes", async () => {
        const findings = await scan(`
            function writeFileSync(path: string, content: string) {}
            const local = {writeFile(path: string, content: string) {}};
            writeFileSync(uri.path, uri.query);
            local.writeFile(uri.path, uri.query);
        `);
        expect(findings).toEqual([]);
    });

    it("does not downgrade an explicit product-specific execution-bearing sink", async () => {
        const spec: TaintSpec = {
            ...vscodeExtensionSpec,
            sinks: [
                ...vscodeExtensionSpec.sinks,
                {
                    kind: "callArgument",
                    name: "execution_config",
                    pattern: "fs.writeFileSync",
                    argPositions: [1],
                    description: "Explicit execution configuration contract",
                    categories: ["rce"],
                    severity: "critical",
                },
            ],
        };
        const findings = await scan(`fs.writeFileSync('.vscode/tasks.json', uri.query);`, spec);
        expect(
            findings.some(
                (f) =>
                    f.sink.name === "execution_config" &&
                    f.sink.categories[0] === "rce" &&
                    f.sink.severity === "critical",
            ),
        ).toBe(true);
        expect(findings.some((f) => f.sink.name === "writeFileSync" && f.sink.categories[0] === "file_integrity")).toBe(
            true,
        );
    });
});
