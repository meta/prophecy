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
import { IslSinks, IslSources, islSpec } from "../../src/static/spec/isl";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

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

    it("adds ISL sources to every VS Code extension source", () => {
        expect(islSpec.sources).toEqual([...vscodeExtensionSpec.sources, ...IslSources]);
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

    it("reports client arguments handed to a runner other than Sapling", async () => {
        const result = await analyzeSource(`
            import * as vscode from "vscode";
            interface Provider {
                runExternalCommand(cwd: string, args: Array<string>): Promise<void>;
                runConfCommand(cwd: string, args: Array<string>): Promise<void>;
            }
            declare const provider: Provider;
            declare function runArcanistCommand(cwd: string, args: Array<string>): Promise<void>;
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { args: Array<string> }) => {
                    void provider.runExternalCommand("/repo", message.args);
                    void provider.runConfCommand("/repo", message.args);
                    void runArcanistCommand("/repo", message.args);
                    void provider.runExternalCommand("/repo", ["get"]);
                });
            }
        `);
        expect(result.findings.map((finding) => finding.sink.name).sort()).toEqual([
            "isl_runArcanistCommand",
            "isl_runConfCommand",
            "isl_runExternalCommand",
        ]);
    });

    it("reports client data piped to a command's standard input, but not its other options", async () => {
        const result = await analyzeSource(`
            import * as vscode from "vscode";
            declare function ejeca(file: string, args: Array<string>, options?: object): Promise<unknown>;
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { stack: string; cwd: string }) => {
                    void ejeca("sl", ["debugimportstack"], { input: message.stack });
                    void ejeca("sl", ["status"], { cwd: message.cwd });
                });
            }
        `);
        expect(result.findings.map((finding) => `${finding.sink.name}: ${finding.sinkLocation.text}`)).toEqual([
            'isl_ejeca_stdin: ejeca("sl", ["debugimportstack"], { input: message.stack })',
        ]);
    });

    it("reports a client-chosen editor setting and a client-chosen path to open", async () => {
        const result = await analyzeSource(`
            import * as vscode from "vscode";
            import * as fs from "fs";
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { config: string; value: string; path: string }) => {
                    void vscode.workspace.getConfiguration().update(message.config, message.value);
                    void vscode.workspace.getConfiguration().update("demo.fixed", message.value);
                    void fs.promises.open(message.path);
                });
            }
        `);
        expect(result.findings.map((finding) => `${finding.sink.name}:${finding.sinkLocation.line}`).sort()).toEqual([
            "fs_open_path:8",
            "vscode_config_update_key:6",
            "vscode_config_update_value:6",
            "vscode_config_update_value:7",
        ]);
    });

    it("treats the output of a wrapped command as a source", async () => {
        const result = await analyzeSource(`
            import { spawn } from "child_process";
            declare function ejeca(file: string, args: Array<string>): Promise<{ stdout: string }>;
            export async function activate() {
                const opener = (await ejeca("sl", ["config", "demo.open-file-cmd"])).stdout;
                spawn(opener, []);
            }
        `);
        expect(result.findings.map((finding) => `${finding.source.pattern} -> ${finding.sink.name}`)).toEqual([
            "ejeca -> spawn",
        ]);
    });

    it("treats the WebSocket upgrade request as a source", async () => {
        const dir = apiBoundaryFixture(
            {
                "main.ts": `
            import { WebSocketServer } from "ws";
            import { exec } from "child_process";
            const server = new WebSocketServer();
            server.on("connection", (socket, request) => {
                exec(new URLSearchParams(request.url).get("cwd"));
                exec(String(socket));
            });
            server.on("close", (socket, request) => { exec(request.url); });
        `,
            },
            `declare module "child_process" { export function exec(command: string): void; }
             declare module "ws" {
                 export class WebSocketServer {
                     on(event: string, callback: (socket: object, request: { url: string }) => void): this;
                 }
             }`,
        );
        try {
            const result = await analyze({ projectDir: dir, spec: islSpec, outputFormat: "json" });
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings.map((finding) => `${finding.source.pattern}:${finding.sinkLocation.line}`)).toEqual([
                "ws.WebSocketServer.on.request:6",
            ]);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
