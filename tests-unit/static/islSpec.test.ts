/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyze, detectSpec } from "../../src/static/analyzer";
import { IslSinks, islSpec } from "../../src/static/spec/isl";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

function projectWithPackage(pkg: object): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "isl-spec-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg));
    return dir;
}

function analyzeSource(source: string) {
    return analyze({
        source,
        fileName: path.join(__dirname, "isl-spec-input.ts"),
        spec: islSpec,
        maxDepth: 5,
        outputFormat: "json",
    });
}

describe("ISL spec", () => {
    it("adds ISL sinks to every VS Code extension sink", () => {
        const names = islSpec.sinks.map((sink) => sink.name);
        expect(names).toEqual([...vscodeExtensionSpec.sinks, ...IslSinks].map((sink) => sink.name));
        const baseNames = new Set(vscodeExtensionSpec.sinks.map((sink) => sink.name));
        const addedNames = IslSinks.map((sink) => sink.name);
        expect(new Set(addedNames).size).toBe(addedNames.length);
        expect(addedNames.some((name) => baseNames.has(name))).toBe(false);
    });

    it.each(["sapling-scm", "isl-server"])("is detected for the %s package", (name) => {
        expect(detectSpec(projectWithPackage({ name, engines: { vscode: "^1.34.0" } }))).toBe(islSpec);
    });

    it("is not detected for other VS Code extensions", () => {
        expect(detectSpec(projectWithPackage({ name: "demo", engines: { vscode: "^1.34.0" } }))).toBe(
            vscodeExtensionSpec,
        );
    });

    it("reports client messages at each command call site", async () => {
        const result = await analyzeSource(`
            import * as vscode from "vscode";
            declare function ejeca(file: string, args: Array<string>, options?: object): Promise<unknown>;
            function runCommand(ctx: object, args: Array<string>) { return ejeca("sl", args); }
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { revs: string; tool: string }) => {
                    void runCommand({}, ["log", "-r", message.revs]);
                    void ejeca("sl", ["resolve", "--tool", message.tool]);
                    void ejeca("sl", ["status"]);
                });
            }
        `);
        expect(result.findings.map((finding) => `${finding.sink.name}: ${finding.sinkLocation.text}`).sort()).toEqual([
            'isl_ejeca_args: ejeca("sl", ["resolve", "--tool", message.tool])',
            'isl_ejeca_args: ejeca("sl", args)',
            'isl_runCommand: runCommand({}, ["log", "-r", message.revs])',
        ]);
    });

    it("follows helpers on a spread Internal object to their command calls", async () => {
        const result = await analyzeSource(`
            import * as vscode from "vscode";
            declare function ejeca(file: string, args: Array<string>, options?: object): Promise<unknown>;
            function runTool(args: Array<string>, cwd: string) { return ejeca("tool", args, { cwd }); }
            function fetchFeatureFlag(name: string) { return name.length > 0; }
            const internalImpl = { runTool, fetchFeatureFlag };
            const Internal: Partial<typeof internalImpl> = { ...internalImpl };
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { args: Array<string>; cwd: string; name: string }) => {
                    void Internal.runTool?.(message.args, message.cwd);
                    void Internal.fetchFeatureFlag?.(message.name);
                });
            }
        `);
        expect(result.findings.map((finding) => `${finding.sink.name}: ${finding.sinkLocation.text}`)).toEqual([
            'isl_ejeca_args: ejeca("tool", args, { cwd })',
        ]);
    });
});
