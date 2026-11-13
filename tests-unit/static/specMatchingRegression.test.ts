/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { TaintSpec } from "../../src/static/spec/types";
import { vscodeSpecWithEnvSource } from "./testUtils";

const imports = `import * as vscode from "vscode"; import { exec, spawn } from "child_process";`;

function analyzeSource(source: string, spec: TaintSpec = vscodeExtensionSpec, typed = true) {
    return analyze({
        source,
        fileName: typed ? path.join(__dirname, "spec-regression-input.ts") : "/no-types/spec-regression-input.ts",
        spec,
        maxDepth: 5,
        outputFormat: "json",
    });
}

function analyzeBody(body: string, spec: TaintSpec = vscodeExtensionSpec, typed = true) {
    return analyzeSource(`${imports} export async function activate() { ${body} }`, spec, typed);
}

function analyzeUri(body: string, spec: TaintSpec = vscodeExtensionSpec, typed = true) {
    return analyzeBody(`vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) { ${body} } });`, spec, typed);
}

describe("Source and sink API identity", () => {
    it("does not invent sources from local identifier names or a shadowed process", async () => {
        const result = await analyzeBody(
            `
            const fileName = "/tmp/fixed";
            const env = "echo safe";
            const process = { env: { COMMAND: "echo safe" } };
            exec(fileName); exec(env); exec(process.env.COMMAND);
        `,
            vscodeSpecWithEnvSource,
        );
        expect(result.findings).toHaveLength(0);
    });

    it("rejects unresolved members on a local API-shaped value", async () => {
        const result = await analyzeSource(
            `
            import { exec } from "child_process";
            import { window } from "vscode";
            export function activate() {
                const process: any = { env: { COMMAND: "safe" } };
                exec(process.env.COMMAND);
                window.registerUriHandler({ handleUri(uri: any) {
                    const vscode: any = { ShellExecution: class {} };
                    new vscode.ShellExecution(uri.query);
                } });
            }
        `,
            vscodeSpecWithEnvSource,
        );
        expect(result.findings).toHaveLength(0);
    });

    it("matches actual document properties and their aliases independently of local spelling", async () => {
        const result = await analyzeBody(`
            const doc = vscode.window.activeTextEditor!.document;
            const localPath = doc.fileName;
            exec("cat " + localPath);
            exec("cat " + doc["fileName"]);
        `);
        expect(result.findings).toHaveLength(2);
        expect(result.findings.every((finding) => finding.source.pattern === "vscode.TextDocument.fileName")).toBe(
            true,
        );
    });

    it("preserves environment aliases and literal property accesses with missing types", async () => {
        const result = await analyzeBody(
            `
            const host = process;
            const variables = host["env"];
            exec(variables.COMMAND);
        `,
            vscodeSpecWithEnvSource,
            false,
        );
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("process.env");
    });

    it("matches namespace and named constructor aliases with and without package types", async () => {
        for (const typed of [true, false]) {
            const result = await analyzeSource(
                `
                ${imports} import { ShellExecution as Run } from "vscode";
                export function activate() {
                    vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                        new Run(uri.query);
                        new vscode.ShellExecution(uri.query);
                    } });
                }
            `,
                vscodeExtensionSpec,
                typed,
            );
            expect(result.findings.filter((finding) => finding.sink.name === "ShellExecution")).toHaveLength(2);
        }
    });

    it("matches fs/promises and node: module APIs with and without package types", async () => {
        for (const typed of [true, false]) {
            const result = await analyzeSource(
                `
                ${imports}
                import * as cp from "node:child_process";
                import { readdir, writeFile } from "fs/promises";
                import { promises as fsp } from "fs";
                import * as nodeFsp from "node:fs/promises";
                export async function activate() {
                    const named = await readdir("/repo");
                    const property = await fsp.readdir("/repo");
                    const prefixed = await nodeFsp.readdir("/repo");
                    cp.exec(named[0]);
                    cp.exec(property[0]);
                    cp.exec(prefixed[0]);
                    await writeFile(named[1], "");
                }
            `,
                vscodeExtensionSpec,
                typed,
            );
            const exec = result.findings.filter((finding) => finding.sink.name === "exec");
            expect(exec).toHaveLength(3);
            expect(exec.every((finding) => finding.source.pattern === "fs.readdir")).toBe(true);
            expect(result.findings.filter((finding) => finding.sink.name === "writeFile_path")).toHaveLength(1);
        }
    });

    it("does not match unrelated or shadowed constructors", async () => {
        const result = await analyzeSource(`
            ${imports}
            class ShellExecution { constructor(value: string) {} }
            class Function { constructor(value: string) {} }
            export function activate() {
                vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                    new ShellExecution(uri.query); new Function(uri.query);
                } });
            }
        `);
        expect(result.findings).toHaveLength(0);
    });

    it("rejects a resolved local namespace masquerading as the VS Code API", async () => {
        const result = await analyzeSource(`
            import { window } from "vscode";
            namespace vscode {
                export class ShellExecution { constructor(value: string) {} }
                export class Webview { html = ""; }
            }
            export function activate() { window.registerUriHandler({ handleUri(uri: any) {
                new vscode.ShellExecution(uri.query);
                const local = new vscode.Webview(); local.html = uri.query;
            } }); }
        `);
        expect(result.findings).toHaveLength(0);
    });

    it("applies constructor shape and property filters", async () => {
        const spec: TaintSpec = {
            ...vscodeExtensionSpec,
            sinks: [
                {
                    kind: "callArgument",
                    name: "options",
                    pattern: "Reader",
                    argPositions: [0],
                    argumentShapes: { 0: "object" },
                    rejectUnknownArgumentShapes: true,
                    objectProperties: ["command"],
                    description: "Execution options",
                    categories: ["rce"],
                },
            ],
        };
        const result = await analyzeSource(
            `
            ${imports} class Reader { constructor(options: unknown) {} }
            export function activate() { vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                new Reader({ label: uri.query });
                new Reader([uri.query]);
                new Reader({ command: uri.query });
            } }); }
        `,
            spec,
        );
        expect(result.findings).toHaveLength(1);
    });

    it("matches a dispatcher sink only for statically resolved operation names", async () => {
        const spec: TaintSpec = {
            ...vscodeExtensionSpec,
            sinks: [
                {
                    kind: "callArgument",
                    name: "prompt",
                    pattern: "vscode.commands.executeCommand",
                    argPositions: [1],
                    argumentValues: { 0: ["demo.prompt"] },
                    description: "Agent prompt",
                    categories: ["prompt_injection"],
                },
            ],
        };
        const result = await analyzeSource(
            `
            ${imports} const PROMPT = "demo.prompt"; enum Commands { Prompt = "demo.prompt" }
            export function activate() { vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                vscode.commands.executeCommand("demo.prompt", { text: uri.query });
                vscode.commands.executeCommand(PROMPT, uri.query);
                vscode.commands.executeCommand(Commands.Prompt, uri.query);
                vscode.commands.executeCommand("demo.show", uri.query);
                vscode.commands.executeCommand(uri.fragment, uri.query);
                vscode.commands.executeCommand("demo.prompt", "fixed", uri.query);
            } }); }
        `,
            spec,
        );
        expect(result.findings.map((finding) => finding.sinkLocation.text).sort()).toEqual([
            'vscode.commands.executeCommand("demo.prompt", { text: uri.query })',
            "vscode.commands.executeCommand(Commands.Prompt, uri.query)",
            "vscode.commands.executeCommand(PROMPT, uri.query)",
        ]);
    });

    it("preserves explicitly configured wildcard source, constructor and assignment rules", async () => {
        const spec: TaintSpec = {
            ...vscodeExtensionSpec,
            sources: [{ kind: "propertyAccess", pattern: "*.query", description: "Configured input" }],
            sinks: [
                {
                    kind: "callArgument",
                    name: "runner",
                    pattern: "*.Runner",
                    description: "Configured constructor",
                    categories: ["rce"],
                },
                {
                    kind: "assignment",
                    name: "html",
                    pattern: "*.html",
                    description: "Configured assignment",
                    categories: ["xss"],
                },
            ],
        };
        const result = await analyzeSource(
            `
            namespace app { export class Runner { constructor(value: string) {} } }
            export function activate() {
                const local = { query: "configured", html: "" };
                new app.Runner(local.query);
                local.html = local.query;
            }
        `,
            spec,
        );
        expect(result.findings.map((finding) => finding.sink.name).sort()).toEqual(["html", "runner"]);
    });

    it("checks every Function body and parameter-syntax argument", async () => {
        const result = await analyzeUri(`
            new Function("x", uri.query)(1);
            Function("x", "y", uri.query)(1, 2);
            new Function("x", uri.query, "return x")();
            const Alias = Function;
            new Alias("x", uri.query)(1);
            Alias("x", uri.query)(1);
            new Function("x", "return x")(1);
        `);
        expect(result.findings).toHaveLength(5);
        expect(result.findings.every((finding) => finding.sink.name === "Function")).toBe(true);
    });
});

describe("Selection value provenance", () => {
    it("keeps bounded literal and const-alias choices clean", async () => {
        const result = await analyzeBody(`
            const choices = ["echo safe", "echo fine"];
            const alias = choices;
            exec((await vscode.window.showQuickPick(["echo safe", "echo fine"]))!);
            exec((await vscode.window.showQuickPick(alias))!);
        `);
        expect(result.findings).toHaveLength(0);
    });

    it("preserves the source of tainted choices", async () => {
        const result = await analyzeBody(`
            const copied = await vscode.env.clipboard.readText();
            exec((await vscode.window.showQuickPick([copied]))!);
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("vscode.env.clipboard.readText");
    });

    it("preserves incoming sources when choices are inserted by mutation", async () => {
        const result = await analyzeBody(`
            const copied = await vscode.env.clipboard.readText();
            const choices = ["echo safe"];
            choices.push(copied);
            exec((await vscode.window.showQuickPick(choices))!);
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("vscode.env.clipboard.readText");
    });

    it("preserves selected object properties without tainting an unrelated detail", async () => {
        const direct = await analyzeBody(`
            const copied = await vscode.env.clipboard.readText();
            const choice = await vscode.window.showQuickPick([{ label: copied, detail: "safe" }]);
            exec(choice!.label); exec(choice!.detail!);
        `);
        expect(direct.findings).toHaveLength(1);
        expect(direct.findings[0].source.pattern).toBe("vscode.env.clipboard.readText");
    });

    it("retains conservative sources for unknown, mutable, or escaped lists", async () => {
        const result = await analyzeSource(`
            ${imports} declare function getChoices(): string[];
            export async function activate() {
                const unknown = getChoices();
                let mutable = ["echo safe"];
                const changed = ["echo safe"];
                const alias = changed; alias.push("echo fine");
                exec((await vscode.window.showQuickPick(unknown))!);
                exec((await vscode.window.showQuickPick(mutable))!);
                exec((await vscode.window.showQuickPick(changed))!);
            }
        `);
        expect(result.findings).toHaveLength(3);
        expect(result.findings.every((finding) => finding.source.pattern === "vscode.window.showQuickPick")).toBe(true);
    });

    it("keeps nested-container and member aliases conservative", async () => {
        const result = await analyzeBody(`
            const choices = ["echo safe"];
            const container = { choices };
            container.choices.push(await vscode.env.clipboard.readText());
            exec((await vscode.window.showQuickPick(choices))!);
            const objects = [{ label: "echo safe" }];
            const first = objects[0];
            first.label = await vscode.env.clipboard.readText();
            exec((await vscode.window.showQuickPick(objects))!.label);
        `);
        expect(result.findings).toHaveLength(2);
    });

    it.each([
        "function mutate() { choices.push(uri.query); }",
        "function mutate() { const update = () => choices.push(uri.query); update(); }",
    ])("retains a finding for a hoisted mutator declared after the selection: %s", async (mutator) => {
        const result = await analyzeSource(`
            ${imports} export function activate() {
                vscode.window.registerUriHandler({ async handleUri(uri: vscode.Uri) {
                    const choices = ["echo safe"];
                    mutate();
                    const selected = await vscode.window.showQuickPick(choices);
                    exec(selected!);
                    ${mutator}
                } });
            }
        `);
        expect(result.findings).toHaveLength(1);
    });

    it("does not let tainted presentation options contaminate a fixed selection", async () => {
        const result = await analyzeBody(`
            const copied = await vscode.env.clipboard.readText();
            exec((await vscode.window.showQuickPick(["echo safe"], { title: copied }))!);
        `);
        expect(result.findings).toHaveLength(0);
    });
});

describe("Explicit scalar-source object properties", () => {
    it("preserves returned input-box fields at a modeled property read", async () => {
        const result = await analyzeSource(`${imports}
            async function collect() {
                const command = await vscode.window.showInputBox();
                return {command};
            }
            function execute(options: {command: string | undefined}) { exec(options.command!); }
            export async function activate() { execute(await collect()); }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
    });

    it("preserves both target-selection and input-box sources in a modeled command return", async () => {
        const result = await analyzeSource(`${imports} declare const targets: string[];
            async function collect() {
                const buildArgs = await vscode.window.showInputBox();
                return {buildArgs};
            }
            function build(target: string, inputs: {buildArgs: string | undefined}) {
                return {command: target + " " + inputs.buildArgs};
            }
            export async function activate() {
                const target = (await vscode.window.showQuickPick(targets))!;
                const inputs = await collect();
                const {command} = build(target, inputs);
                exec(command);
            }
        `);
        expect(result.findings).toHaveLength(2);
        expect(new Set(result.findings.map((finding) => finding.source.pattern))).toEqual(
            new Set(["vscode.window.showInputBox", "vscode.window.showQuickPick"]),
        );
    });

    it("keeps a clean sibling independent of an explicitly tainted scalar field", async () => {
        const result = await analyzeBody(`
            const command = await vscode.window.showInputBox();
            const options = {label: command, command: "echo safe"};
            exec(options.command);
            exec(options.label!);
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
    });

    it("preserves nested scalar paths across branch joins", async () => {
        const result = await analyzeSource(`${imports} declare const flag: boolean;
            export async function activate() {
                const command = await vscode.window.showInputBox();
                let options: {nested: {command: string | undefined, label: string}};
                if (flag) options = {nested: {command, label: "safe"}};
                else options = {nested: {command: "echo safe", label: "safe"}};
                exec(options.nested.command!);
                exec(options.nested.label);
            }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
    });

    it.each([false, true])("keeps property-sensitive helper calls independent of cache order %s", async (reverse) => {
        const calls = [`execute({label: command, command: "echo safe"});`, `execute({label: "safe", command});`];
        const result = await analyzeSource(`${imports}
            function execute(options: {label: string | undefined, command: string | undefined}) {
                exec(options.command!);
            }
            export async function activate() {
                const command = await vscode.window.showInputBox();
                ${reverse ? calls.reverse().join("\n") : calls.join("\n")}
            }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
        expect(
            result.findings[0].propagationChain.some(
                (step) => step.kind === "objectProperty" && step.description === "command",
            ),
        ).toBe(true);
    });
});

describe("Executable argv operands", () => {
    it.each([
        ["node", '["-e", uri.query]', "rce"],
        ["node", '["--eval", uri.query]', "rce"],
        ["node", '["--require", uri.query, "fixed.js"]', "rce"],
        ["node", '["-e", "console.log(1)", "--", uri.query]', "arg_injection"],
        ["node", '["fixed.js", uri.query]', "arg_injection"],
        ["node", '["-e", "console.log(1)", uri.query]', "rce"],
        ["python3", '["-c", uri.query]', "rce"],
        ["python3", '["-m", uri.query]', "rce"],
        ["python3", '["-c", "print(1)", uri.query]', "arg_injection"],
        ["/bin/bash", '["-lc", uri.query]', "rce"],
        ["/bin/bash", '["-c", "echo safe", uri.query]', "arg_injection"],
        ["/bin/bash", '["fixed.sh", uri.query]', "arg_injection"],
        ["pwsh", '["-Command", "Write-Host", uri.query]', "rce"],
        ["powershell.exe", '["-File", "fixed.ps1", uri.query]', "arg_injection"],
        ["pwsh", '["-NoProfile", "-File", uri.query]', "rce"],
        ["pwsh", '["-NoProfile", "-File", "fixed.ps1", uri.query]', "arg_injection"],
        ["pwsh", '["-ExecutionPolicy", "Bypass", "-File", uri.query]', "rce"],
        ["tool", "[uri.query]", "arg_injection"],
    ])("classifies %s %s as %s", async (binary, argv, category) => {
        const result = await analyzeUri(`spawn(${JSON.stringify(binary)}, ${argv});`);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.categories).toEqual([category]);
        expect(() => JSON.stringify(result.findings)).not.toThrow();
    });

    it("preserves literal argv identity through const aliases", async () => {
        const result = await analyzeUri(
            `const args = ["-c", "echo safe", uri.query]; const alias = args; spawn("bash", alias);`,
        );
        expect(result.findings[0].sink.categories).toEqual(["arg_injection"]);
    });

    it("keeps mutated, spread, and unknown argv conservative", async () => {
        const result = await analyzeUri(`
            const args = ["-c", "echo safe", uri.query]; args.splice(0, 2);
            spawn("bash", args);
            spawn("bash", [...uri.query.split(" ")]);
            const other: string[] = JSON.parse(uri.query);
            spawn("bash", other);
        `);
        expect(result.findings).toHaveLength(3);
        expect(result.findings.every((finding) => finding.sink.categories.includes("rce"))).toBe(true);
    });

    it("treats shell-enabled argv as code even after a fixed executable", async () => {
        const result = await analyzeUri(`spawn("tool", [uri.query], { shell: true });`);
        expect(result.findings[0].sink.categories).toEqual(["rce"]);
    });
});

describe("Promisified sinks", () => {
    it("matches the wrapped function through const aliases and inline calls with and without package types", async () => {
        for (const typed of [true, false]) {
            const result = await analyzeSource(
                `
                ${imports} import { promisify } from "util";
                const run = promisify(exec);
                const alias = run;
                export function activate() {
                    vscode.window.registerUriHandler({ async handleUri(uri: vscode.Uri) {
                        await run(uri.query, { cwd: "/tmp" });
                        await alias(uri.query);
                        await promisify(exec)(uri.query);
                    } });
                }
            `,
                vscodeExtensionSpec,
                typed,
            );
            expect(result.findings).toHaveLength(3);
            expect(result.findings.every((finding) => finding.sink.name === "exec" && finding.promisified)).toBe(true);
        }
    });

    it("keeps execFile argument positions for namespace imports", async () => {
        const result = await analyzeSource(`
            ${imports} import * as util from "util"; import * as cp from "child_process";
            const runFile = util.promisify(cp.execFile);
            export function activate() {
                vscode.window.registerUriHandler({ async handleUri(uri: vscode.Uri) {
                    await runFile(uri.query, []);
                    await runFile("tool", [uri.query]);
                } });
            }
        `);
        expect(result.findings.map((finding) => [finding.sink.name, finding.sink.categories]).sort()).toEqual([
            ["execFile", ["rce"]],
            ["execFile_args", ["arg_injection"]],
        ]);
    });

    it("does not unwrap a local promisify or a promisified non-sink", async () => {
        const result = await analyzeSource(`
            ${imports} import * as util from "util";
            function promisify(fn: unknown) { return (value: string) => Promise.resolve(value); }
            function local(value: string, callback: () => void) {}
            const run = promisify(exec);
            const runLocal = util.promisify(local);
            export function activate() {
                vscode.window.registerUriHandler({ async handleUri(uri: vscode.Uri) {
                    await run(uri.query);
                    await runLocal(uri.query);
                } });
            }
        `);
        expect(result.findings).toHaveLength(0);
    });
});

describe("Workspace command output", () => {
    const root = `function root() { const folders = vscode.workspace.workspaceFolders; return folders![0].uri.fsPath; }`;

    it("taints promisified exec output from a command run in a workspace folder", async () => {
        const result = await analyzeSource(`
            ${imports} import { promisify } from "util";
            const run = promisify(exec);
            ${root}
            export async function activate() {
                const { stdout } = await run("tool --list-json", { cwd: root(), timeout: 1000 });
                const entries: { name: string }[] = JSON.parse(stdout);
                for (const entry of entries) {
                    await run(\`tool --describe \${entry.name}\`, { cwd: root() });
                }
            }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("child_process.exec");
        expect(result.findings[0].sourceLocation.line).toBe(6);
        expect(result.findings[0].sinkLocation.line).toBe(9);
    });

    it("taints sync and callback output for document and workspace-folder locations", async () => {
        const result = await analyzeSource(`
            ${imports} import { execSync, execFile } from "child_process"; import * as path from "path";
            function showLog(folder: vscode.WorkspaceFolder) {
                execFile("git", ["branch", "--show-current"], { cwd: folder.uri.fsPath }, (error, stdout) => {
                    exec(\`git log \${stdout.trim()}\`);
                });
            }
            export function activate() {
                const document = vscode.window.activeTextEditor!.document;
                const branch = execSync("git branch --show-current", { cwd: path.dirname(document.uri.fsPath) });
                exec(\`git log \${branch}\`);
                showLog(vscode.workspace.workspaceFolders![0]);
            }
        `);
        expect(result.findings.map((finding) => finding.source.pattern).sort()).toEqual([
            "child_process.execSync",
            "execFile.stdout",
        ]);
    });

    it("keeps the command's own provenance on its output", async () => {
        const result = await analyzeSource(`
            ${imports} import { promisify } from "util";
            const run = promisify(exec);
            ${root}
            export async function activate() {
                const tool = vscode.workspace.getConfiguration("demo").get<string>("tool")!;
                const { stdout } = await run(\`\${tool} --list\`, { cwd: root() });
                await run(\`echo \${stdout}\`);
            }
        `);
        const atOutput = result.findings.filter((finding) => finding.sinkLocation.line === 8);
        expect(atOutput.map((finding) => finding.source.pattern).sort()).toEqual([
            "WorkspaceConfiguration.get",
            "child_process.exec",
        ]);
    });

    it("does not taint commands run elsewhere or results that are not output", async () => {
        const result = await analyzeSource(`
            ${imports} import { promisify } from "util"; import { execSync } from "child_process"; import * as os from "os";
            const run = promisify(exec);
            ${root}
            export async function activate(context: vscode.ExtensionContext) {
                const home = execSync("tool --list", { cwd: os.homedir() });
                const bundled = await run("tool --list", { cwd: context.extensionPath });
                const unspecified = await run("tool --list");
                const child = exec("tool --list", { cwd: root() });
                exec(\`tool \${home} \${bundled.stdout} \${unspecified.stdout} \${child.pid}\`);
            }
        `);
        expect(result.findings).toHaveLength(0);
    });
});

describe("Registered providers and webview HTML", () => {
    it("taints registered document-provider URIs without treating every similarly named method as an entry point", async () => {
        const result = await analyzeBody(`
            const provider = { provideTextDocumentContent(uri: vscode.Uri) { exec(uri.query); return ""; } };
            const unregistered = { provideTextDocumentContent(uri: vscode.Uri) { exec(uri.query); return ""; } };
            vscode.workspace.registerTextDocumentContentProvider("demo", provider);
            void unregistered;
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("provideTextDocumentContent.uri");
    });

    it("handles class provider registrations", async () => {
        const result = await analyzeSource(`
            ${imports} class Provider {
                provideTextDocumentContent(uri: vscode.Uri) { exec(uri.query); return ""; }
            }
            export function activate() { vscode.workspace.registerTextDocumentContentProvider("demo", new Provider()); }
        `);
        expect(result.findings).toHaveLength(1);
    });

    it("analyzes registered language feature provider methods with clean parameters", async () => {
        const result = await analyzeSource(`
            ${imports} class Lenses {
                constructor(private config: vscode.WorkspaceConfiguration) {}
                provideCodeLenses(document: vscode.TextDocument) {
                    exec(\`\${this.config.get<string>("toolPath")} \${document.uri.path}\`);
                    return [];
                }
            }
            class Unregistered {
                provideCodeLenses(document: vscode.TextDocument) {
                    exec(vscode.workspace.getConfiguration("demo").get<string>("toolPath")!);
                    return [];
                }
            }
            export function activate() {
                const config = vscode.workspace.getConfiguration("demo");
                vscode.languages.registerCodeLensProvider({ language: "demo" }, new Lenses(config));
                const hover = { provideHover(document: vscode.TextDocument) { exec(document.getText()); return undefined; } };
                vscode.languages.registerHoverProvider({ language: "demo" }, hover);
                void Unregistered;
            }
        `);
        expect(result.findings).toHaveLength(2);
        expect(result.findings.map((finding) => finding.source.pattern).sort()).toEqual([
            "TextDocument.getText",
            "WorkspaceConfiguration.get",
        ]);
        expect(result.findings.map((finding) => finding.sinkLocation.line).sort((a, b) => a - b)).toEqual([5, 18]);
    });

    it("reports actual webview assignments through HTML and serialized script data", async () => {
        const result = await analyzeUri(`
            const panel = vscode.window.createWebviewPanel("demo", "Demo", vscode.ViewColumn.One);
            panel.webview.html = "<p>" + uri.query + "</p>";
            panel.webview["html"] = "<script>const data=" + JSON.stringify({ value: uri.query }) + ";</script>";
        `);
        expect(result.findings).toHaveLength(2);
        expect(result.findings.every((finding) => finding.sink.name === "webview_html")).toBe(true);
    });

    it("preserves raw constructor fields at a modeled webview sink", async () => {
        const result = await analyzeSource(`
            ${imports} class Renderer {
                private content: string;
                constructor(raw: string) { this.content = raw; }
                render() { return this.content; }
            }
            export function activate() { vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                const renderer = new Renderer(uri.query);
                const panel = vscode.window.createWebviewPanel("demo", "Demo", vscode.ViewColumn.One);
                panel.webview.html = "<p>" + renderer.render() + "</p>";
            } }); }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.name).toBe("webview_html");
    });

    it("does not interpret local escapeHtml names as generic sanitizers", async () => {
        const result = await analyzeSource(`
            ${imports} function escapeHtml(value: string) { return value.replace(/</g, "&lt;"); }
            export function activate() { vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                const panel = vscode.window.createWebviewPanel("demo", "Demo", vscode.ViewColumn.One);
                panel.webview.html = escapeHtml(uri.query);
            } }); }
        `);
        expect(result.findings).toHaveLength(1);
    });

    it("keeps unrelated local HTML fields and numeric-converted webview content clean", async () => {
        const result = await analyzeUri(`
            const local = { html: "" }; local.html = uri.query;
            const panel = vscode.window.createWebviewPanel("demo", "Demo", vscode.ViewColumn.One);
            panel.webview.html = "<p>" + parseInt(uri.query, 10) + "</p>";
        `);
        expect(result.findings).toHaveLength(0);
    });
});
