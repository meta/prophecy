/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { ExecSink } from "../../src/static/spec/sinks";
import { TaintFinding, TaintSpec } from "../../src/static/spec/types";
import { vscodeSpecWithEnvSource } from "./testUtils";

function analyzeSource(source: string, fileName = "/src/extension.ts") {
    return analyze({
        source,
        fileName,
        spec: vscodeExtensionSpec,
        maxDepth: 5,
        outputFormat: "text",
    });
}

function analyzeSourceWithDebug(source: string, spec: TaintSpec = vscodeExtensionSpec) {
    return analyze({
        source,
        fileName: "/src/extension.ts",
        spec,
        maxDepth: 5,
        outputFormat: "text",
        analysisDebug: true,
    });
}

function analyzeSourceWithSpec(source: string, spec: TaintSpec) {
    return analyze({
        source,
        fileName: "/src/extension.ts",
        spec,
        maxDepth: 5,
        outputFormat: "text",
    });
}

/** Commands named by argument-injection findings for shell-quoted values, sorted. */
function quotedArgumentCommands(findings: TaintFinding[]): string[] {
    return findings.flatMap((f) => (f.quotedArgumentOf != null ? [f.quotedArgumentOf] : [])).sort();
}

describe("Static Taint Analysis", () => {
    describe("URI Handler RCE (T226511721 pattern)", () => {
        it("should detect direct uri.query → exec flow", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const prompt = uri.query;
                            exec(prompt);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should detect uri.query → string concat → exec flow", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const params = uri.query;
                            const command = "git clone " + params;
                            exec(command);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should detect uri.query → template literal → exec flow", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const repo = uri.query;
                            exec(\`git clone \${repo} /tmp/repo\`);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Sanitization", () => {
        it("should apply shlex.quote only to shell-command sinks", async () => {
            const result = await analyzeSource(`
                import * as fs from "fs";
                import * as shlex from "shlex";
                import * as vscode from "vscode";
                import { spawn } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("agent new --title " + escaped);
                            void vscode.commands.executeCommand(escaped);
                            spawn(escaped, []);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(3);
            expect(result.findings.map((f) => f.sink.name).sort()).toEqual(["executeCommand", "sendText", "spawn"]);
            expect(quotedArgumentCommands(result.findings)).toEqual(["agent"]);
        });

        it("should not treat shell quoting as argument-injection sanitization", async () => {
            const result = await analyzeSource(`
                import { spawn } from "child_process";
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            spawn("git", [shlex.quote(uri.query)]);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["arg_injection"]);
        });

        it("should report a quoted value used as the entire shell command", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(shlex.quote(uri.query));
                            terminal.sendText(shlex.quote(uri.path) + " --version");
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(2);
            expect(result.findings.every((f) => f.sink.name === "sendText")).toBe(true);
        });

        it("should report quoted arguments in fixed template and array commands as argument injection", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`agent new --title \${escaped}\`);

                            const command = ["agent", "new", "--title"];
                            command.push(escaped);
                            terminal.sendText(command.join(" "));
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(2);
            expect(new Set(quotedArgumentCommands(result.findings))).toEqual(new Set(["agent"]));
            expect(quotedArgumentCommands(result.findings)).toHaveLength(result.findings.length);
        });

        it("should keep quoted code passed to command interpreters tainted", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("sh -c " + escaped);
                            terminal.sendText("ssh host " + escaped);
                            terminal.sendText("echo '" + escaped + "'");
                            terminal.sendText("echo $(" + escaped + ")");

                            const safeCommand = "agent run " + escaped;
                            terminal.sendText("sh -c '" + safeCommand + "'");

                            const shellCommand = ["bash", "-c"];
                            shellCommand.push(escaped);
                            terminal.sendText(shellCommand.join(" "));
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(6);
            expect(result.findings.every((f) => f.sink.categories.includes("rce"))).toBe(true);
            expect(result.findings.every((f) => f.sink.name === "sendText")).toBe(true);
        });

        it("should retain fixed-command context across quoted arguments", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const first = shlex.quote(uri.query);
                            const second = shlex.quote(uri.fragment);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(
                                \`agent new --title \${first} --label \${second}\`,
                            );
                            terminal.sendText(
                                "agent new --title " + first + " --label " + second,
                            );
                        }
                    });
                }
            `);

            // `uri.query` and `uri.fragment` are one source, so one finding per call.
            expect(result.findings).toHaveLength(2);
            expect(new Set(quotedArgumentCommands(result.findings))).toEqual(new Set(["agent"]));
            expect(quotedArgumentCommands(result.findings)).toHaveLength(result.findings.length);
        });

        it("should not recover shell context after an unquoted dynamic prefix", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const raw = await vscode.window.showInputBox();
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`\${raw} agent --title \${escaped}\`);
                            terminal.sendText(raw + " agent --title " + escaped);
                        }
                    });
                }
            `);

            expect(result.findings.filter((f) => f.source.pattern === "handleUri.uri")).toHaveLength(2);
        });

        it("should keep mixed raw and quoted array arguments tainted", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const raw = await vscode.window.showInputBox();
                            const command = ["agent", "new"];
                            command.push(raw!);
                            command.push(shlex.quote(uri.query));
                            vscode.window.createTerminal("Agent").sendText(command.join(" "));
                        }
                    });
                }
            `);

            expect(result.findings.some((f) => f.source.pattern === "handleUri.uri")).toBe(true);
            expect(result.findings.some((f) => f.source.pattern === "vscode.window.showInputBox")).toBe(true);
        });

        it("should keep reporting a quoted argument redirected by fixed text", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText("echo " + escaped + " >> ~/.bashrc");
                        }
                    });
                }
            `);

            // Quoting stops the value adding a redirect, but the fixed text after
            // it writes the value into a shell rc file.
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["rce"]);
            expect(
                result.findings[0].propagationChain.some(
                    (step) => step.description === "quoted argument is redirected to a file by fixed text",
                ),
            ).toBe(true);
        });

        it("should treat a quoted argument piped into a denied command as command execution", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("echo " + escaped + " | sh");
                            terminal.sendText(\`echo \${escaped} | grep x | bash\`);
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.categories[0])).toEqual(["rce", "rce"]);
            expect(
                result.findings.every((f) =>
                    f.propagationChain.some((step) => step.description.startsWith("quoted argument is piped into")),
                ),
            ).toBe(true);
        });

        it("should only treat stdout redirected to a real file as writing the value", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const q = shlex.quote(uri.query);
                            const t = vscode.window.createTerminal("Agent");
                            t.sendText("agent run " + q + " 2>/dev/null");
                            t.sendText("agent run " + q + " 2>&1 | grep x");
                            t.sendText("echo " + q + " > /dev/null");
                            t.sendText("echo " + q + " &> out.txt");
                            t.sendText("echo " + q + " 1> out.txt");
                            t.sendText("agent run " + q + " 2>&1 | sh");
                        }
                    });
                }
            `);

            const byLine = result.findings
                .slice()
                .sort((a, b) => a.sinkLocation.line - b.sinkLocation.line)
                .map((f) => f.sink.categories[0]);
            // stderr redirects, fd duplication, and /dev/null keep argument injection;
            // stdout into a file, and a pipe into sh after 2>&1, are command execution.
            expect(byLine).toEqual(["arg_injection", "arg_injection", "arg_injection", "rce", "rce", "rce"]);
        });

        it("should keep a quoted argument piped into an ordinary command as argument injection", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("echo " + escaped + " | grep x");
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.categories[0])).toEqual(["arg_injection"]);
            expect(result.findings[0].quotedArgumentOf).toBe("echo");
        });

        it("should treat cd to a quoted directory before another command as command execution", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("cd " + escaped + " && ./build.sh");
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.categories[0])).toEqual(["rce"]);
        });

        it("should keep cd to a quoted directory alone as argument injection", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("cd " + escaped);
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.categories[0])).toEqual(["arg_injection"]);
            expect(result.findings[0].quotedArgumentOf).toBe("cd");
        });

        it("should ignore redirection characters inside quoted fixed text", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`agent run \${escaped} --sep '>'\`);
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.categories[0])).toEqual(["arg_injection"]);
        });

        it("should keep argument injection when the text after a quoted value is unknown", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            const flag = uri.fragment.length > 0 ? " --codex" : "";
                            terminal.sendText("agent new --title " + escaped + flag);
                        }
                    });
                }
            `);

            // `flag` is not tainted, so its runtime text is unknown rather than dangerous.
            expect(result.findings.map((f) => f.sink.categories[0])).toEqual(["arg_injection"]);
        });

        it("should report quoted arguments to ordinary commands as argument injection", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("hyperloop_client -job_id " + escaped);
                            terminal.sendText(\`/irnext-debugger:debug-logs Analyze \${escaped}\`);
                        }
                    });
                }
            `);

            expect(quotedArgumentCommands(result.findings)).toEqual(["hyperloop_client", "irnext-debugger:debug-logs"]);
            expect(result.findings).toHaveLength(2);
        });

        it("should deny versioned, suffixed, and path-qualified interpreters", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("python3.11 " + escaped);
                            terminal.sendText("node18 " + escaped);
                            terminal.sendText("bash.exe " + escaped);
                            terminal.sendText("/usr/local/bin/perl5.36 " + escaped);
                            terminal.sendText("npx " + escaped);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(5);
            expect(result.findings.every((f) => f.sink.categories.includes("rce"))).toBe(true);
            expect(result.findings.some((f) => f.quotedArgumentOf != null)).toBe(false);
        });

        it("should only strip a version or .exe suffix from a denied command name", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText("shasum " + escaped);
                            terminal.sendText("nodetool " + escaped);
                        }
                    });
                }
            `);

            // \`shasum\` and \`nodetool\` start with denied names but are other programs.
            expect(quotedArgumentCommands(result.findings)).toEqual(["nodetool", "shasum"]);
            expect(result.findings).toHaveLength(2);
        });

        it("should not name a placeholder as the command of a later quoted value", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            // A command composed earlier ends in a satisfied quoted
                            // argument, so the later value follows a placeholder word.
                            const base = "agent run " + shlex.quote((await vscode.window.showInputBox()) ?? "");
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`\${base} \${escaped}\`);
                        }
                    });
                }
            `);

            const argument = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(argument).toHaveLength(1);
            expect(argument[0].sink.categories).toEqual(["arg_injection"]);
            expect(argument[0].quotedArgumentOf).toBeUndefined();
            expect(argument[0].sink.description).toContain("a quoted command");
            expect(argument[0].sink.description).not.toContain("prophecy_quoted_argument");
        });

        it("should credit a value quoted after a tainted command word", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                function command(): string {
                    const bin = vscode.workspace.getConfiguration("demo").get<string>("bin", "demo");
                    return \`\${bin} run --\`;
                }

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            exec(\`\${command()} --name \${shlex.quote(uri.query)}\`);
                        }
                    });
                }
            `);

            // The tainted command word is still command execution; the quoted value
            // after it is an argument of that unknown command.
            const configuration = result.findings.filter((f) => f.source.pattern === "WorkspaceConfiguration.get");
            const argument = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(configuration).toHaveLength(1);
            expect(configuration[0].sink.categories).toEqual(["rce"]);
            expect(argument).toHaveLength(1);
            expect(argument[0].sink.categories).toEqual(["arg_injection"]);
            expect(argument[0].quotedArgumentOf).toBeUndefined();
        });

        it("should keep the fixed command for a value quoted after a tainted argument", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const name = (await vscode.window.showInputBox()) ?? "";
                            vscode.window.createTerminal("Agent").sendText(
                                \`agent run \${uri.fragment} --name \${shlex.quote(name)}\`,
                            );
                        }
                    });
                }
            `);

            const uri = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            const name = result.findings.filter((f) => f.source.pattern === "vscode.window.showInputBox");
            expect(uri).toHaveLength(1);
            expect(uri[0].sink.categories).toEqual(["rce"]);
            expect(name).toHaveLength(1);
            expect(name[0].sink.categories).toEqual(["arg_injection"]);
            expect(name[0].quotedArgumentOf).toBe("agent");
        });

        it("should credit values quoted element-wise with map and joined with spaces", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const args: string[] = [uri.query];
                            const names = [(await vscode.window.showInputBox()) ?? ""];
                            const quotedNames = names.map(shlex.quote);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`agent run \${args.map(arg => shlex.quote(arg)).join(" ")}\`);
                            terminal.sendText(\`agent show \${quotedNames.join(" ")}\`);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(2);
            expect(result.findings.every((f) => f.sink.categories.includes("arg_injection"))).toBe(true);
            expect(quotedArgumentCommands(result.findings)).toEqual(["agent", "agent"]);
        });

        it("should not credit map quoting joined with a shell separator or applied to another value", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const args: string[] = [uri.query];
                            const names = [(await vscode.window.showInputBox()) ?? ""];
                            const terminal = vscode.window.createTerminal("Agent");
                            // Each quoted word becomes its own command after ";".
                            terminal.sendText(\`agent run \${args.map(arg => shlex.quote(arg)).join(";")}\`);
                            // The callback quotes a fixed value and returns the element unquoted.
                            terminal.sendText(\`agent show \${names.map(name => name + shlex.quote("x")).join(" ")}\`);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(2);
            expect(result.findings.every((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("should keep fixed-command context across an untainted quoted argument", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                function provider(): string {
                    return "default";
                }

                function binary(): string {
                    return "agent";
                }

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`agent run --provider \${shlex.quote(provider())} \${shlex.quote(uri.query)}\`);
                            // A dynamic quoted command word could still be a shell.
                            terminal.sendText(\`\${shlex.quote(binary())} -c \${shlex.quote(uri.fragment)}\`);
                        }
                    });
                }
            `);

            const byCategory = result.findings.map((f) => f.sink.categories.join(",")).sort();
            expect(byCategory).toEqual(["arg_injection", "rce"]);
            expect(quotedArgumentCommands(result.findings)).toEqual(["agent"]);
        });

        it("should treat a const string prefix as fixed command text", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                const COMMAND = "/irnext-debugger:debug-logs";
                const ALIAS = COMMAND;

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`\${COMMAND} Analyze \${escaped}\`);
                            terminal.sendText(ALIAS + " Analyze " + escaped);
                        }
                    });
                }
            `);

            // Resolving the prefix makes each quoted value an argument of the slash
            // command (argument injection) rather than unknown shell text (rce).
            expect(result.findings).toHaveLength(2);
            expect(new Set(quotedArgumentCommands(result.findings))).toEqual(new Set(["irnext-debugger:debug-logs"]));
            expect(quotedArgumentCommands(result.findings)).toHaveLength(result.findings.length);
        });

        it("should keep a const prefix naming a denied command or a mutable prefix tainted", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                const SHELL = "bash -c";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let prefix = "agent run";
                            prefix = uri.fragment.length > 0 ? "sh -c" : prefix;
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`\${SHELL} \${escaped}\`);
                            terminal.sendText(prefix + " " + escaped);
                        }
                    });
                }
            `);

            const uriFindings = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(uriFindings).toHaveLength(2);
            expect(uriFindings.every((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("should keep fixed-command context across a numerically sanitized value", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const line = Number(uri.fragment);
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`/irnext-debugger:debug-logs Line \${line} of \${escaped}\`);
                            terminal.sendText("agent show --line " + parseInt(uri.path, 10) + " " + escaped);
                        }
                    });
                }
            `);

            // Context survives the number, so each quoted value is an argument of its
            // command (argument injection) rather than unknown shell text (rce).
            expect(result.findings).toHaveLength(2);
            expect(new Set(quotedArgumentCommands(result.findings))).toEqual(
                new Set(["agent", "irnext-debugger:debug-logs"]),
            );
            expect(quotedArgumentCommands(result.findings)).toHaveLength(result.findings.length);
        });

        it("should lose fixed-command context when a number is part of the command word", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const version = Number(uri.fragment);
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`run\${version} \${escaped}\`);
                        }
                    });
                }
            `);

            // Context lost: the quoted value is reported as command execution,
            // not as a quoted argument.
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["rce"]);
            expect(result.findings[0].quotedArgumentOf).toBeUndefined();
        });

        it("should not treat a non-numeric rce sanitizer as a numeric word", async () => {
            const spec: TaintSpec = {
                ...vscodeExtensionSpec,
                sanitizers: [
                    ...vscodeExtensionSpec.sanitizers,
                    {
                        kind: "callReturnValue",
                        pattern: "customEscape",
                        description: "Custom escaper",
                        categories: ["rce"],
                    },
                ],
            };
            const result = await analyzeSourceWithSpec(
                `
                import * as shlex from "shlex";
                import * as vscode from "vscode";
                declare function customEscape(value: string): string;

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const label = customEscape(uri.fragment);
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`agent \${label} \${escaped}\`);
                        }
                    });
                }
            `,
                spec,
            );

            // The custom sanitizer clears its own value, but does not keep the
            // context going, so the quoted value after it is command execution.
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["rce"]);
            expect(result.findings[0].quotedArgumentOf).toBeUndefined();
        });

        it("should not continue context for a numeric sanitizer scoped away from rce", async () => {
            const spec: TaintSpec = {
                ...vscodeExtensionSpec,
                sanitizers: [
                    ...vscodeExtensionSpec.sanitizers,
                    {
                        kind: "callReturnValue",
                        pattern: "toHtmlNumber",
                        description: "Numeric conversion for HTML only",
                        categories: ["xss"],
                        numeric: true,
                    },
                ],
            };
            const result = await analyzeSourceWithSpec(
                `
                import * as shlex from "shlex";
                import * as vscode from "vscode";
                declare function toHtmlNumber(value: string): number;

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const n = toHtmlNumber((await vscode.window.showInputBox()) ?? "");
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`agent \${n} \${escaped}\`);
                        }
                    });
                }
            `,
                spec,
            );

            // The number has its own source so the quoted value's finding stays distinct.
            const quoted = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(quoted).toHaveLength(1);
            expect(quoted[0].sink.categories).toEqual(["rce"]);
            expect(quoted[0].quotedArgumentOf).toBeUndefined();
        });

        it("should not treat a number concatenated with shell text as a numeric word", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const part = Number((await vscode.window.showInputBox()) ?? "") + "; sh -c";
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`agent \${part} \${escaped}\`);
                        }
                    });
                }
            `);

            // \`part\` ends in \`sh -c\`, so the quoted value after it is command execution.
            const quoted = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(quoted).toHaveLength(1);
            expect(quoted[0].sink.categories).toEqual(["rce"]);
            expect(quoted[0].quotedArgumentOf).toBeUndefined();
        });

        it("should not continue context for a numeric sanitizer restricted to other sinks", async () => {
            const spec: TaintSpec = {
                ...vscodeExtensionSpec,
                sanitizers: [
                    ...vscodeExtensionSpec.sanitizers,
                    {
                        kind: "callReturnValue",
                        pattern: "toExecNumber",
                        description: "Numeric conversion for exec only",
                        categories: ["rce"],
                        sinkNames: ["exec"],
                        numeric: true,
                    },
                ],
            };
            const result = await analyzeSourceWithSpec(
                `
                import * as shlex from "shlex";
                import * as vscode from "vscode";
                declare function toExecNumber(value: string): number;

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const n = toExecNumber((await vscode.window.showInputBox()) ?? "");
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`agent \${n} \${escaped}\`);
                        }
                    });
                }
            `,
                spec,
            );

            const quoted = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(quoted).toHaveLength(1);
            expect(quoted[0].sink.categories).toEqual(["rce"]);
            expect(quoted[0].quotedArgumentOf).toBeUndefined();
        });

        it("should not treat a number transformed by another sanitizer as a numeric word", async () => {
            const spec: TaintSpec = {
                ...vscodeExtensionSpec,
                sanitizers: [
                    ...vscodeExtensionSpec.sanitizers,
                    {
                        kind: "callReturnValue",
                        pattern: "customEscape",
                        description: "Custom escaper",
                        categories: ["rce"],
                    },
                ],
            };
            const result = await analyzeSourceWithSpec(
                `
                import * as shlex from "shlex";
                import * as vscode from "vscode";
                declare function customEscape(value: string): string;

                export function activate() {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const part = customEscape(Number((await vscode.window.showInputBox()) ?? "") + "; sh -c");
                            const escaped = shlex.quote(uri.query);
                            vscode.window.createTerminal("Agent").sendText(\`agent \${part} \${escaped}\`);
                        }
                    });
                }
            `,
                spec,
            );

            // \`part\` was built into shell text before \`customEscape\`, so it is not a number.
            const quoted = result.findings.filter((f) => f.source.pattern === "handleUri.uri");
            expect(quoted).toHaveLength(1);
            expect(quoted[0].sink.categories).toEqual(["rce"]);
            expect(quoted[0].quotedArgumentOf).toBeUndefined();
        });

        it("should lose fixed-command context after an unsanitized value", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(\`agent show \${uri.fragment} \${escaped}\`);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["rce"]);
            expect(result.findings[0].quotedArgumentOf).toBeUndefined();
        });

        it("should reject denied commands and transformed quoted values", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const escaped = shlex.quote(uri.query);
                            const terminal = vscode.window.createTerminal("Agent");
                            // A quoted value can still be an option: --upload-pack=<cmd>.
                            terminal.sendText("git fetch " + escaped);
                            terminal.sendText("if true; then agent " + escaped);
                            terminal.sendText(
                                "agent --title " + escaped.replace("x", "y"),
                            );
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(3);
            expect(result.findings.every((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("should treat a fixed quoted binary as the command for a quoted argument", async () => {
            const result = await analyzeSource(`
                import * as path from "path";
                import * as shlex from "shlex";
                import * as vscode from "vscode";
                import * as os from "os";

                const binary = path.join(os.homedir(), ".agent-cli", "builds", "acli");

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const terminal = vscode.window.createTerminal("Agent");
                            terminal.sendText(
                                \`\${shlex.quote(binary)} --title \${shlex.quote(uri.query)}\`,
                            );
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(new Set(quotedArgumentCommands(result.findings))).toEqual(new Set(["acli"]));
            expect(quotedArgumentCommands(result.findings)).toHaveLength(result.findings.length);
        });

        it("should reject a non-literal quoted command", async () => {
            const result = await analyzeSource(`
                import * as shlex from "shlex";
                import * as vscode from "vscode";

                declare const shellPath: string;

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            vscode.window.createTerminal("Agent").sendText(
                                \`\${shlex.quote(shellPath)} -c \${shlex.quote(uri.query)}\`,
                            );
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should keep JSON and URI transformations tainted without context proof", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const serialized = JSON.stringify(uri.query);
                            const encoded = encodeURIComponent(uri.fragment);
                            exec(serialized);
                            eval(serialized);
                            eval(encoded);
                            fetch("https://example.com/items/" + encoded);
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.name).sort()).toEqual(["eval", "eval", "exec", "fetch"]);
        });

        it("should scope numeric conversion to string-injection categories", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec, spawn } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const pid = parseInt(uri.query, 10);
                            const code = Number(uri.fragment);
                            exec("kill -9 " + pid);
                            eval(code);
                            fetch("http://" + pid);
                            vscode.env.openExternal(vscode.Uri.parse("http://" + code));
                            spawn("tool", [String(pid)]);
                        }
                    });
                }
            `);

            expect(result.findings.map((f) => f.sink.name).sort()).toEqual(["fetch", "openExternal", "spawn_args"]);
        });

        it("should fail closed for an unscoped sanitizer from a JSON spec", async () => {
            const spec = {
                entryFunctions: ["activate"],
                sources: [
                    {
                        kind: "callReturnValue",
                        pattern: "source",
                        description: "Attacker input",
                    },
                ],
                sinks: [ExecSink],
                sanitizers: [
                    {
                        kind: "callReturnValue",
                        pattern: "sanitize",
                        description: "Unscoped sanitizer",
                    },
                ],
            } as unknown as TaintSpec;
            const result = await analyzeSourceWithSpec(
                `
                import { exec } from "child_process";
                declare function source(): string;
                declare function sanitize(value: string): string;

                export function activate() {
                    exec(sanitize(source()));
                }
            `,
                spec,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].propagationChain.some((step) => step.kind === "sanitizer")).toBe(true);
        });

        it("should fail closed for a categorized sanitizer and an uncategorized sink", async () => {
            const spec: TaintSpec = {
                entryFunctions: ["activate"],
                sources: [
                    {
                        kind: "callReturnValue",
                        pattern: "source",
                        description: "Attacker input",
                    },
                ],
                sinks: [
                    {
                        ...ExecSink,
                        categories: [],
                    },
                ],
                sanitizers: [
                    {
                        kind: "callReturnValue",
                        pattern: "sanitize",
                        description: "RCE sanitizer",
                        categories: ["rce"],
                    },
                ],
            };
            const result = await analyzeSourceWithSpec(
                `
                import { exec } from "child_process";
                declare function source(): string;
                declare function sanitize(value: string): string;

                export function activate() {
                    exec(sanitize(source()));
                }
            `,
                spec,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].propagationChain.some((step) => step.kind === "sanitizer")).toBe(true);
        });
    });

    describe("Expression wrappers", () => {
        it("should preserve taint through satisfies expressions", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const command = uri.query satisfies string;
                            exec(command);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.name).toBe("exec");
        });
    });

    describe("Control flow", () => {
        it("should ignore sinks after a terminal return", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            return;
                            exec(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Interprocedural analysis", () => {
        it("should follow taint through helper functions", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runCommand(cmd: string) {
                    exec(cmd);
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const userInput = uri.query;
                            runCommand(userInput);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Entry point detection", () => {
        it("should discover registerUriHandler entry points", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            console.log(uri.query);
                        }
                    });
                }
            `);

            expect(result.entryPointCount).toBeGreaterThanOrEqual(1);
        });

        it("should discover registerCommand entry points", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.commands.registerCommand("myext.hello", (arg: string) => {
                        console.log(arg);
                    });
                }
            `);

            expect(result.entryPointCount).toBeGreaterThanOrEqual(1);
        });

        it("should not treat registerCommand parameters as attacker-controlled", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.commands.registerCommand("myext.run", (arg: string) => {
                        exec(arg);
                    });
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should analyze an inline registerCommand callback only as its own entry point", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                async function run() {
                    const input = await vscode.window.showInputBox();
                    exec(input!);
                }

                export function activate() {
                    vscode.commands.registerCommand("myext.run", async () => {
                        await run();
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
            expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
        });

        it("should ignore a clean captured instance passed through an unrelated helper argument", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class State {
                    refresh() {}
                }

                async function run(state: State) {
                    const input = await vscode.window.showInputBox();
                    exec(input!);
                    state.refresh();
                }

                export function activate() {
                    const state = new State();
                    vscode.commands.registerCommand("myext.run", async () => {
                        await run(state);
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
            expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
        });

        it("should analyze a registerCommand callback at its definition when it captures taint", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = process.env.BUILD_COMMAND;
                    vscode.commands.registerCommand("myext.run", () => {
                        exec(command!);
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("process.env");
            expect(result.findings[0].handle).toContain("Entry function: activate()");
        });

        it("should ignore unrelated outer taint when choosing the command entry point", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const unrelated = process.env.UNRELATED;
                    void unrelated;
                    vscode.commands.registerCommand("myext.run", async () => {
                        const input = await vscode.window.showInputBox();
                        exec(input!);
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
            expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
        });

        it("should distinguish a shadowed callback variable from outer taint", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const input = process.env.UNRELATED;
                    vscode.commands.registerCommand("myext.run", async () => {
                        const input = await vscode.window.showInputBox();
                        exec(input!);
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
            expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
        });

        it("should retain definition-site analysis for captured instance-field taint", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class CommandHolder {
                    constructor(public command: string) {}
                }

                export function activate() {
                    const holder = new CommandHolder(process.env.BUILD_COMMAND!);
                    vscode.commands.registerCommand("myext.run", () => {
                        exec(holder.command);
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("process.env");
            expect(result.findings[0].handle).toContain("Entry function: activate()");
        });

        it("should retain definition-site analysis for state shared by command callbacks", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class CommandHolder {
                    command = "safe";

                    load() {
                        this.command = process.env.BUILD_COMMAND!;
                    }

                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const holder = new CommandHolder();
                    vscode.commands.registerCommand("myext.load", () => {
                        holder.load();
                    });
                    vscode.commands.registerCommand("myext.run", () => {
                        holder.run();
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("process.env");
            expect(result.findings[0].handle).toContain("Entry function: activate()");
        });

        it("should retain definition-site analysis for methods on captured clean instances", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    run() {
                        const command = process.env.BUILD_COMMAND;
                        exec(command!);
                    }
                }

                export function activate() {
                    const runner = new Runner();
                    vscode.commands.registerCommand("myext.run", () => {
                        runner.run();
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(
                result.findings.some(
                    (f) => f.source.pattern === "process.env" && f.handle.includes("Entry function: activate()"),
                ),
            ).toBe(true);
        });

        it("should ignore a tainted sibling field when the callback reads a clean field", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class CommandHolder {
                    constructor(
                        public command: string,
                        public label: string,
                    ) {}
                }

                export function activate() {
                    const holder = new CommandHolder(process.env.BUILD_COMMAND!, "safe");
                    vscode.commands.registerCommand("myext.run", async () => {
                        void holder.label;
                        const input = await vscode.window.showInputBox();
                        exec(input!);
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
            expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
        });

        it("should preserve tainted this fields captured by an arrow callback", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Controller {
                    constructor(public command: string) {}

                    register() {
                        vscode.commands.registerCommand("myext.run", () => {
                            exec(this.command);
                        });
                    }
                }

                export function activate() {
                    const controller = new Controller(process.env.BUILD_COMMAND!);
                    controller.register();
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("process.env");
            expect(result.findings[0].handle).toContain("Entry function: activate()");
        });

        it("should not treat dynamic this in a function callback as captured", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Controller {
                    constructor(public command: string) {}

                    register() {
                        vscode.commands.registerCommand("myext.run", async function(this: unknown) {
                            void this;
                            const input = await vscode.window.showInputBox();
                            exec(input!);
                        });
                    }
                }

                export function activate() {
                    const controller = new Controller(process.env.BUILD_COMMAND!);
                    controller.register();
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("vscode.window.showInputBox");
            expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
        });

        it("should bridge tainted executeCommand arguments through constant command names", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                const COMMANDS = {
                    run: "myext.run",
                };

                export function activate(context: vscode.ExtensionContext) {
                    vscode.commands.registerCommand(COMMANDS.run, (arg: string) => {
                        exec(arg);
                    });
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            void vscode.commands.executeCommand(COMMANDS.run, uri.query);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("handleUri.uri");
        });

        it("should bridge executeCommand into property-access command handlers", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                const handlers = {
                    run: (value: string) => {
                        exec(value);
                    },
                };

                export function activate(context: vscode.ExtensionContext) {
                    vscode.commands.registerCommand("myext.run", handlers.run);
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            void vscode.commands.executeCommand("myext.run", uri.query);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("handleUri.uri");
        });

        it("should resolve command wrappers with an injected handler parameter", async () => {
            // The wrapper prepends a synthetic argument, then forwards command
            // arguments through a spread; resolution must compensate for that
            // offset.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function registerTrackedCommand(
                    command: string,
                    callback: (chronicle: unknown, value: string) => void,
                ): void;
                function registerTrackedCommand(
                    command: string,
                    callback: (chronicle: unknown, value: string) => void,
                ) {
                    vscode.commands.registerCommand(command, (...args: unknown[]) => {
                        callback({}, ...args as [string]);
                    });
                }

                export function activate() {
                    registerTrackedCommand("myext.run", (_chronicle, value) => {
                        exec(value);
                    });
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            void vscode.commands.executeCommand("myext.run", uri.query);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("handleUri.uri");
        });

        it("should resolve wrappers that move command and handler arguments", async () => {
            // The wrapper moves the command and callback parameters, then
            // forwards handler arguments only through a spread.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function registerAndTrackCommand(
                    eventName: string,
                    getErrorCode: () => string,
                    command: string,
                    callback: (value: string) => void,
                ) {
                    void eventName;
                    void getErrorCode;
                    vscode.commands.registerCommand(command, (...args: unknown[]) => {
                        callback(...args as [string]);
                    });
                }

                export function activate() {
                    registerAndTrackCommand("event", () => "error", "myext.run", value => {
                        exec(value);
                    });
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            void vscode.commands.executeCommand("myext.run", uri.query);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("handleUri.uri");
        });

        it("should not classify unrelated registerCommand functions", async () => {
            const result = await analyzeSource(`
                function registerCommand(name: string, callback: () => void) {
                    void name;
                    void callback;
                }

                export function activate() {
                    registerCommand("myext.run", () => {});
                }
            `);

            expect(result.entryPointCount).toBe(1);
        });

        it("should retain definition-site analysis for wrapper callbacks that capture this", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function registerTrackedCommand(
                    command: string,
                    callback: (chronicle: unknown) => void,
                ) {
                    vscode.commands.registerCommand(command, (...args: unknown[]) => {
                        callback({}, ...args);
                    });
                }

                class Controller {
                    constructor(public command: string) {}

                    register() {
                        registerTrackedCommand("myext.run", () => {
                            exec(this.command);
                        });
                    }
                }

                export function activate() {
                    const controller = new Controller(process.env.BUILD_COMMAND!);
                    controller.register();
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("process.env");
            expect(result.findings[0].handle).toContain("Entry function: activate()");
        });

        it("should resolve named message event handlers as tainted entry points", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";
                import WebSocket from "ws";

                export function activate() {
                    const ws = new WebSocket("wss://example.test");
                    function onMessage(data: any) {
                        const message = JSON.parse(data);
                        exec(message.command);
                    }
                    ws.on("message", onMessage);
                }

            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "onMessage.data" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should resolve variable message event handlers as tainted entry points", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";
                import WebSocket from "ws";

                export function activate() {
                    const ws = new WebSocket("wss://example.test");
                    const onMessage = (data: any) => {
                        exec(data.toString());
                    };
                    ws.addListener("message", onMessage);
                }

            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "onMessage.data" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });
    });

    describe("Fallback entry point detection (T255561860)", () => {
        it("should discover exported arrow functions as entry points", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";

                export const runBuild = (cmd: string) => {
                    exec(cmd);
                };
            `);

            // No activate() or VS Code entry points → fallback should find runBuild
            expect(result.entryPointCount).toBeGreaterThanOrEqual(1);
        });

        it("should discover exported class methods as entry points", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";

                export class Builder {
                    run(cmd: string) {
                        exec(cmd);
                    }
                }
            `);

            // No activate() or VS Code entry points → fallback should find Builder.run
            expect(result.entryPointCount).toBeGreaterThanOrEqual(1);
        });

        it("should discover function-valued class properties as entry points", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";

                export class Builder {
                    label = "build";
                    run = (cmd: string) => {
                        exec(cmd);
                    };
                }
            `);

            expect(result.entryPointCount).toBe(1);
        });
    });

    describe("Various sinks", () => {
        it("should distinguish path control from unverified content persistence", async () => {
            const result = await analyzeSource(`
                import * as fs from "fs";
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            fs.writeFile(uri.fsPath, "fixed", () => {});
                            fs.writeFileSync(uri.path, "fixed");
                            fs.writeFileSync("/tmp/cache.json", uri.query);
                            fs.writeFileSync(".vscode/tasks.json", uri.query);
                            await vscode.workspace.fs.writeFile(
                                vscode.Uri.file("/tmp/cache.bin"),
                                new TextEncoder().encode(uri.query),
                            );
                            fs.writeFileSync("/tmp/authorized_keys", uri.query);
                        }
                    });
                }
            `);

            expect([...new Set(result.findings.map((f) => f.sink.name))].sort()).toEqual([
                "vscode_writeFile",
                "writeFileSync",
                "writeFileSync_path",
                "writeFile_path",
            ]);
            const content = result.findings.filter((f) => f.sink.categories.includes("file_integrity"));
            expect(content).toHaveLength(4);
            expect(content.every((f) => f.sink.severity === "low")).toBe(true);
        });

        it("should detect taint flowing to execSync", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { execSync } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            execSync(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("execSync"))).toBe(true);
        });

        it("should detect taint flowing to eval", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            eval(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("eval"))).toBe(true);
        });
    });

    describe("Destructuring", () => {
        it("should track taint through object destructuring", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const { query } = uri;
                            exec(query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Object literal properties", () => {
        it("should track taint through a shorthand property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        async handleUri(uri: vscode.Uri) {
                            const initCommands = JSON.parse(uri.query);
                            const config = {
                                type: "lldb",
                                request: "attach",
                                name: "n",
                                initCommands,
                            };
                            await vscode.debug.startDebugging(undefined, config);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should not taint a clean sibling property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { command, cwd: "/tmp" };
                    exec(options.cwd);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should retain taint on the matching property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { command, cwd: "/tmp" };
                    exec(options.command);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should keep nested object literal siblings clean", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { process: { command, cwd: "/tmp" } };
                    exec(options.process.cwd);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should filter object destructuring by property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { command, cwd: "/tmp" };
                    const { cwd } = options;
                    exec(cwd);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should retain taint through matching object destructuring", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { command, cwd: "/tmp" };
                    const { command: selectedCommand } = options;
                    exec(selectedCommand);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should retain taint through nested source properties", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const options = vscode.workspace.getConfiguration().get<{
                        launch: { command: string };
                    }>("options");
                    exec(options!.launch.command);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve property precision across calls", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function run(options: { command: string; cwd: string }) {
                    exec(options.command);
                    exec(options.cwd);
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    run({ command: command!, cwd: "/tmp" });
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should filter literal element access by property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { command, cwd: "/tmp" };
                    exec(options["cwd"]);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should conservatively taint dynamic element access", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { command, cwd: "/tmp" };
                    const key = Math.random() > 0.5 ? "command" : "cwd";
                    exec(options[key]);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should consume property paths when enumerating object values", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = { process: { command, cwd: "/tmp" } };
                    exec(Object.values(options).join(" "));
                    exec(Object.entries(options).flat().join(" "));
                }
            `);

            expect(result.findings).toHaveLength(2);
        });

        it("should map an opened notebook URI onto the returned document", async () => {
            const result = await analyzeSource(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export async function activate() {
                    const fileName = vscode.window.activeTextEditor!.document.fileName;
                    const uri = vscode.Uri.file(fileName);
                    const document = await vscode.workspace.openNotebookDocument(uri);
                    exec(document.uri);
                }
            `,
                __dirname + "/typed-document-input.ts",
            );

            expect(result.findings).toHaveLength(1);
        });

        it("should not taint an unrelated method property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const options = {
                        command,
                        cleanMethod: () => "/tmp",
                    };
                    exec(options.cleanMethod());
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Closure capture", () => {
        // Nested functions receive outer taint by capture rather than
        // arguments, so closure analysis must include captured state.
        it("should track taint into a named nested arrow function", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const run = () => { exec(uri.query); };
                            run();
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should track taint into an inline callback body", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            [1].forEach(() => { exec(uri.query); });
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should track taint through nested closures over an array (S-style daemon flow)", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import * as child_process from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const body = JSON.parse(uri.query) as {
                                machine: string;
                                paths: string[];
                            };
                            const args = ["bind", body.machine];
                            const operate = async () => {
                                await Promise.all(
                                    body.paths.map(p => {
                                        const argCopy = args.slice();
                                        argCopy.push(p);
                                        child_process.spawn("/usr/bin/machinectl", argCopy, {});
                                    }),
                                );
                            };
                            void operate();
                        },
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("spawn"))).toBe(true);
        });

        it("keeps capture taint gained on a later loop iteration for a stored closure", async () => {
            // The first iteration's closure captures `cmd` clean; merging it
            // with a later iteration's must not drop the tainted capture.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { execFile } from "child_process";

                class Holder { constructor(readonly get: () => string) {} }

                export function activate() {
                    const configured = vscode.workspace.getConfiguration().get<string>("command", "");
                    let cmd = "safe";
                    let holder = new Holder(() => "");
                    for (const _ of [1, 2]) {
                        holder = new Holder(() => cmd);
                        cmd = configured;
                    }
                    execFile(holder.get(), []);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("calls a closure stored in an object literal through a constructor parameter property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Client {
                    constructor(private readonly options: { getConfig: () => { command: string } }) {
                        this.init();
                    }
                    private init() { exec(this.options.getConfig().command); }
                }

                export function activate() {
                    new Client({
                        getConfig: () => {
                            const config = vscode.workspace.getConfiguration("demo");
                            return { command: config.get<string>("command", "") };
                        },
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.name).toBe("exec");
        });

        it("calls a closure stored under a shorthand object property", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function run(options: { getCommand: () => string }) {
                    exec(options.getCommand());
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command", "");
                    const getCommand = () => command;
                    run({ getCommand });
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("calls a function reached through a spread object and a variable alias", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runCommand(command: string) {
                    exec(command);
                }

                const registryImpl = { runCommand };
                const registry = registryImpl as Partial<typeof registryImpl>;
                const helpers = { ...registry };

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command", "");
                    const run = helpers.runCommand;
                    run?.(command);
                }
            `);

            expect(result.findings.map((finding) => finding.sink.name)).toEqual(["exec"]);
        });

        it("lets a later member override the same member of a spread object", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                const base = { run: (command: string) => exec(command) };
                const safe = { ...base, run: (command: string) => command.length };

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command", "");
                    safe.run(command);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("does not call a sibling closure of the object literal", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function run(options: { getCommand: () => string; getName: () => string }) {
                    exec(options.getName());
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command", "");
                    run({ getCommand: () => command, getName: () => "demo" });
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Container mutation", () => {
        it("should taint an array that a tainted value is pushed into", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import * as child_process from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const args: string[] = ["bind"];
                            args.push(uri.query);
                            child_process.spawn("/bin/x", args, {});
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Subprocess sink severity split", () => {
        const spawnCase = (body: string) => `
            import * as vscode from "vscode";
            import * as child_process from "child_process";

            export function activate(context: vscode.ExtensionContext) {
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        const x = uri.query;
                        ${body}
                    }
                });
            }
        `;

        it("treats a tainted BINARY as rce", async () => {
            const result = await analyzeSource(spawnCase(`child_process.spawn(x, ["--version"], {});`));
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings[0].sink.categories).toContain("rce");
        });

        it("treats tainted ARGS to a fixed binary as arg_injection, not rce", async () => {
            const result = await analyzeSource(spawnCase(`child_process.spawn("/usr/bin/git", ["log", x], {});`));
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings[0].sink.categories).toContain("arg_injection");
            expect(result.findings[0].sink.severity).toBe("high");
        });

        it("upgrades tainted args back to rce when argv[0] is a shell", async () => {
            const result = await analyzeSource(spawnCase(`child_process.execFile("/bin/sh", ["-c", x]);`));
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings[0].sink.categories).toContain("rce");
        });

        for (const shell of ["bash", "/bin/sh", "/bin/zsh"]) {
            it(`upgrades find -exec ${shell} through a wrapper to rce`, async () => {
                const result = await analyzeSource(
                    spawnCase(`
                        function runCommand(command: string, args: string[]) {
                            child_process.execFile(command, args);
                        }
                        runCommand("/usr/bin/find", [
                            ".",
                            "-exec",
                            "${shell}",
                            "-c",
                            \`echo \${x}\`,
                            "_",
                            "{}",
                            ";",
                        ]);
                    `),
                );
                const finding = result.findings.find(
                    (f) => f.sink.categories.includes("rce") && f.sinkLocation.text === "`echo ${x}`",
                );
                expect(finding).toBeDefined();
            });
        }

        it("keeps non-command find arguments as arg injection", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    child_process.execFile("/usr/bin/find", [
                        ".",
                        "-name",
                        x,
                        "-exec",
                        "bash",
                        "-c",
                        "echo safe",
                        "_",
                        "{}",
                        ";",
                    ]);
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("arg_injection"))).toBe(true);
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(false);
        });

        it("keeps find -exec without a shell as arg injection", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    child_process.execFile("/usr/bin/find", [
                        ".",
                        "-exec",
                        "/bin/mv",
                        "{}",
                        x,
                        ";",
                    ]);
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("arg_injection"))).toBe(true);
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(false);
        });

        it("upgrades tainted args back to rce when shell:true is set", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/ruby", ["-", x], {shell: true});`),
            );
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings[0].sink.categories).toContain("rce");
        });

        it("upgrades tainted args when shell:true is in an aliased options object", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const options = {shell: true};
                    const alias = options;
                    child_process.spawn("/usr/bin/ruby", ["-", x], alias);
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("does not classify cwd-only option taint as rce", async () => {
            const result = await analyzeSource(spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {cwd: x});`));
            expect(result.findings).toHaveLength(0);
        });

        it("recognizes the spawn(command, options) overload", async () => {
            const result = await analyzeSource(spawnCase(`child_process.spawn("/usr/bin/git", {cwd: x});`));
            expect(result.findings).toHaveLength(0);
        });

        it("does not report a known benign option", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {timeout: x});`),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("does not classify cwd-only taint through an options alias as rce", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const options = {cwd: x};
                    const alias = options;
                    child_process.spawn("/usr/bin/git", ["status"], alias);
                `),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("retains env option taint as rce", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {env: {PATH: x}});`),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("does not report taint under an env var that only passes data", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {env: {LOG_DIR: x}});`),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("does not report a data env var built in a separate object", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const env = {LOG_DIR: x, MODE: "fast"};
                    child_process.execFile("/usr/bin/git", ["status"], {cwd: "/tmp", env});
                `),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("does not report a data env var through an options wrapper", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const wrapped = {options: {env: {LOG_DIR: x}}};
                    const {options} = wrapped;
                    child_process.spawn("/usr/bin/git", ["status"], options);
                `),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("matches execution-bearing env var names case-insensitively", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {env: {Path: x}});`),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("matches execution-bearing env var prefixes", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.execFile("/usr/bin/git", ["fetch"], {env: {GIT_SSH_COMMAND: x}});`),
            );
            expect(result.findings.some((f) => f.sink.name === "execFile_options")).toBe(true);
        });

        it("retains taint spread into env, whose keys are unknown", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {env: {...JSON.parse(x)}});`),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("retains taint under a computed env key", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const name = "LOG_DIR";
                    child_process.spawn("/usr/bin/git", ["status"], {env: {[name]: x}});
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("retains a whole env object from elsewhere", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const env = JSON.parse(x);
                    child_process.spawn("/usr/bin/git", ["status"], {env});
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("retains env taint through an options wrapper", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const wrapped = {options: {env: {PATH: x}}};
                    const {options} = wrapped;
                    child_process.spawn("/usr/bin/git", ["status"], options);
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("suppresses cwd taint through an options wrapper", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const wrapped = {options: {cwd: x}};
                    const {options} = wrapped;
                    child_process.spawn("/usr/bin/git", ["status"], options);
                `),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("retains config taint when shell is explicitly enabled", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["status"], {shell: x});`),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("keeps tainted args as argument injection when shell is false", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.spawn("/usr/bin/git", ["log", x], {shell: false});`),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("arg_injection"))).toBe(true);
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(false);
        });

        it("retains an unknown whole options object conservatively", async () => {
            const result = await analyzeSource(
                spawnCase(`
                    const options = JSON.parse(x);
                    child_process.spawn("/usr/bin/git", ["status"], options);
                `),
            );
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("distinguishes the execFile(file, options) overload through an import alias", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import {execFile as runFile} from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            runFile("/usr/bin/git", {env: {PATH: uri.query}});
                        }
                    });
                }
            `);
            expect(result.findings.some((f) => f.sink.name === "execFile_options")).toBe(true);
            expect(result.findings.some((f) => f.sink.name === "execFile_args")).toBe(false);
        });

        it("distinguishes the execFile(file, args, options) overload", async () => {
            const result = await analyzeSource(
                spawnCase(`child_process.execFile("/usr/bin/git", ["status"], {env: {PATH: x}});`),
            );
            expect(result.findings.some((f) => f.sink.name === "execFile_options")).toBe(true);
            expect(result.findings.some((f) => f.sink.name === "execFile_args")).toBe(false);
        });

        it("keeps execFile argv separate from cwd-only option taint", async () => {
            const result = await analyzeSource(spawnCase(`child_process.execFile("/usr/bin/git", [x], {cwd: x});`));
            expect(result.findings.some((f) => f.sink.name === "execFile_args")).toBe(true);
            expect(result.findings.some((f) => f.sink.name === "execFile_options")).toBe(false);
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(false);
        });

        it("treats an ambiguous execFile second argument conservatively as options", async () => {
            const result = await analyzeSource(spawnCase(`child_process.execFile("/usr/bin/git", JSON.parse(x));`));
            expect(result.findings.some((f) => f.sink.name === "execFile_options")).toBe(true);
            expect(result.findings.some((f) => f.sink.name === "execFile_args")).toBe(false);
        });

        it("leaves child_process.exec as rce", async () => {
            const result = await analyzeSource(spawnCase(`child_process.exec(x);`));
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings[0].sink.categories).toContain("rce");
        });
    });

    describe("vscode-languageclient server launch (T271372254)", () => {
        // `x` is a workspace setting. `construct` is the LanguageClient call.
        const languageClientCase = (construct: string, preamble = "") => `
            import * as vscode from "vscode";
            import { LanguageClient } from "vscode-languageclient/node";

            export function activate() {
                const x = vscode.workspace.getConfiguration("demo").get<string>("value", "");
                ${preamble}
                ${construct};
            }
        `;
        const serverCase = (serverOptions: string, preamble = "") =>
            languageClientCase(`new LanguageClient("demo", "Demo", ${serverOptions}, {})`, preamble);
        const sinks = (findings: TaintFinding[]) =>
            findings.map((f) => `${f.sink.name}:${f.sink.categories.join(",")}`).sort();

        it("treats a tainted command as rce", async () => {
            const result = await analyzeSource(serverCase(`{command: x}`));
            expect(sinks(result.findings)).toEqual(["LanguageClient:rce"]);
        });

        it("treats a tainted Node module as rce", async () => {
            const result = await analyzeSource(serverCase(`{module: x}`));
            expect(sinks(result.findings)).toEqual(["LanguageClient:rce"]);
        });

        it("treats tainted args as argument injection", async () => {
            const result = await analyzeSource(serverCase(`{command: "demo", args: ["lsp", x]}`));
            expect(sinks(result.findings)).toEqual(["LanguageClient_args:arg_injection"]);
            expect(result.findings[0].sink.severity).toBe("high");
        });

        it("upgrades tainted args to rce when the options set shell:true", async () => {
            const result = await analyzeSource(
                serverCase(`{command: "demo", args: ["lsp", x], options: {shell: true}}`),
            );
            expect(sinks(result.findings)).toEqual(["LanguageClient_args:rce"]);
            expect(result.findings[0].sink.severity).toBe("critical");
        });

        it("upgrades tainted args when shell:true is in a shorthand options variable", async () => {
            const result = await analyzeSource(
                serverCase(
                    `{command: "demo", args, options}`,
                    `
                    const options = {shell: true};
                    const args = ["--lazy-mode", x];
                `,
                ),
            );
            expect(sinks(result.findings)).toEqual(["LanguageClient_args:rce"]);
        });

        it("keeps tainted args as argument injection when shell is false", async () => {
            const result = await analyzeSource(
                serverCase(`{command: "demo", args: ["lsp", x], options: {shell: false}}`),
            );
            expect(sinks(result.findings)).toEqual(["LanguageClient_args:arg_injection"]);
        });

        it("checks the shell option of the run or debug server that carries the taint", async () => {
            const shellInRun = await analyzeSource(
                serverCase(`{
                run: {command: "demo", args: [x], options: {shell: true}},
                debug: {command: "demo", args: ["--debug"]},
            }`),
            );
            expect(sinks(shellInRun.findings)).toEqual(["LanguageClient_args:rce"]);

            const shellInDebug = await analyzeSource(
                serverCase(`{
                run: {command: "demo", args: [x]},
                debug: {command: "demo", args: ["--debug"], options: {shell: true}},
            }`),
            );
            expect(sinks(shellInDebug.findings)).toEqual(["LanguageClient_args:arg_injection"]);
        });

        it("treats an execution-bearing env var as rce", async () => {
            const result = await analyzeSource(serverCase(`{command: "demo", options: {env: {PATH: x}}}`));
            expect(sinks(result.findings)).toEqual(["LanguageClient_options:rce"]);
        });

        it("does not report cwd or a data env var", async () => {
            const result = await analyzeSource(serverCase(`{command: "demo", options: {cwd: x, env: {LOG_DIR: x}}}`));
            expect(result.findings).toHaveLength(0);
        });

        it("does not report a tainted transport", async () => {
            const result = await analyzeSource(serverCase(`{command: "demo", transport: {kind: 3, port: x}}`));
            expect(result.findings).toHaveLength(0);
        });

        it("reports a whole server options object from a setting once, as rce", async () => {
            const result = await analyzeSource(
                serverCase(`vscode.workspace.getConfiguration("demo").get<any>("server")`),
            );
            expect(sinks(result.findings)).toEqual(["LanguageClient:rce"]);
        });

        it("finds server options at argument 1 when the id is omitted", async () => {
            const result = await analyzeSource(languageClientCase(`new LanguageClient("Demo", {command: x}, {})`));
            expect(sinks(result.findings)).toEqual(["LanguageClient:rce"]);
        });

        it("does not report client options when the id is omitted", async () => {
            const result = await analyzeSource(
                languageClientCase(
                    `new LanguageClient("Demo", {command: "demo"}, {initializationOptions: {command: x}})`,
                ),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("does not report a tainted client name", async () => {
            const result = await analyzeSource(
                languageClientCase(`new LanguageClient("demo", x, {command: "demo"}, {})`),
            );
            expect(result.findings).toHaveLength(0);
        });

        it("matches the client exported from the package root", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { LanguageClient } from "vscode-languageclient";

                export function activate() {
                    const x = vscode.workspace.getConfiguration("demo").get<string>("value", "");
                    new LanguageClient("demo", "Demo", {command: x}, {});
                }
            `);
            expect(sinks(result.findings)).toEqual(["LanguageClient:rce"]);
        });

        it("matches a super(...) call to a sink constructor", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                class LoggedShellExecution extends vscode.ShellExecution {
                    constructor(command: string) {
                        super(command);
                    }
                }

                export function activate() {
                    const x = vscode.workspace.getConfiguration("demo").get<string>("value", "");
                    new LoggedShellExecution(x);
                }
            `);
            expect(sinks(result.findings)).toEqual(["ShellExecution:rce"]);
            expect(result.findings[0].sinkLocation.text).toBe("super(command)");
        });
    });

    describe("Receiver/this tracking (T255561856)", () => {
        // Unresolved methods with no tainted arguments must still propagate
        // receiver taint. Built-ins such as toString() have no analyzable body.
        it("should propagate taint through method calls on tainted receiver", async () => {
            // uri.query is tainted. uri.query.toString() calls a method ON the
            // tainted value with no arguments. The receiver (uri.query) is tainted,
            // so the return value should carry taint through to exec().
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const cmd = uri.query.toString();
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should propagate taint through chained method calls", async () => {
            // Each chained call (.trim(), .toLowerCase()) has a tainted receiver,
            // so taint flows through the entire chain: uri.query → trim() → toLowerCase() → exec
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const cmd = uri.query.trim().toLowerCase();
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should track taint stored in this fields", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Handler {
                    private command = "";

                    handleUri(uri: vscode.Uri) {
                        this.command = uri.query;
                        exec(this.command);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler(new Handler());
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) =>
                    f.propagationChain.some((step) => step.description.includes("assigned to 'this.command'")),
                ),
            ).toBe(true);
        });

        it("should carry this field taint into methods on the same instance", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Handler {
                    private command = "";

                    handleUri(uri: vscode.Uri) {
                        this.command = uri.query;
                        this.runCommand();
                    }

                    runCommand() {
                        exec(this.command);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler(new Handler());
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should clear this field taint on clean reassignment", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Handler {
                    private command = "";

                    handleUri(uri: vscode.Uri) {
                        this.command = uri.query;
                        this.command = "git status";
                        this.runCommand();
                    }

                    runCommand() {
                        exec(this.command);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler(new Handler());
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should carry this field taint through ordinary TypeScript setter methods", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import { exec } from "child_process";

                class Runner {
                    private command = "";

                    configure(command: string) {
                        this.command = command;
                    }

                    run() {
                        exec(this.command);
                    }
                }

                export function runBuild() {
                    const runner = new Runner();
                    runner.configure(process.env.BUILD_CMD);
                    runner.run();
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "process.env" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should preserve this field taint when a reset method is not called", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import { exec } from "child_process";

                class Runner {
                    private command = "";

                    configure(command: string) {
                        this.command = command;
                    }

                    reset() {
                        this.command = "git status";
                    }

                    run() {
                        exec(this.command);
                    }
                }

                export function runBuild() {
                    const runner = new Runner();
                    runner.configure(process.env.BUILD_CMD);
                    runner.run();
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "process.env" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should clear this field taint through ordinary TypeScript reset methods", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import { exec } from "child_process";

                class Runner {
                    private command = "";

                    configure(command: string) {
                        this.command = command;
                    }

                    reset() {
                        this.command = "git status";
                    }

                    run() {
                        exec(this.command);
                    }
                }

                export function runBuild() {
                    const runner = new Runner();
                    runner.configure(process.env.BUILD_CMD);
                    runner.reset();
                    runner.run();
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings.length).toBe(0);
        });
    });

    describe("If/else branch isolation (T255561854)", () => {
        it("should NOT report when taint is introduced in then-branch and sink is in else-branch", async () => {
            // cmd is only assigned tainted data inside the `if` block.
            // In the `else` block, cmd is still "safe" (its initial value).
            // The else-branch exec(cmd) should NOT be flagged.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = "safe";
                            if (uri.path === "/danger") {
                                cmd = uri.query;
                            } else {
                                exec(cmd);
                            }
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should report when taint is introduced in then-branch and sink is after the if/else", async () => {
            // After the if/else, cmd MIGHT be tainted (it was tainted in the
            // then-branch). A sink after the if/else should be flagged because
            // we can't know which branch was taken at runtime.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = "safe";
                            if (uri.path === "/danger") {
                                cmd = uri.query;
                            }
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should NOT merge instance field taint from a branch that returns early", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    private command = "safe";

                    configure(command: string) {
                        this.command = command;
                    }

                    run() {
                        exec(this.command);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const runner = new Runner();
                            if (uri.path === "/danger") {
                                runner.configure(uri.query);
                                return;
                            }
                            runner.run();
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should NOT merge taint from a branch that returns early", async () => {
            // The then-branch taints cmd but returns — it can never reach exec.
            // Only the else-branch (where cmd is "safe") falls through to exec.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = "safe";
                            if (uri.path === "/danger") {
                                cmd = uri.query;
                                return;
                            }
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should NOT merge taint from a branch with nested if/else that always exits", async () => {
            // The then-branch has a nested if/else where both paths return.
            // The branch always exits, so its taint should not merge.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = "safe";
                            if (uri.path === "/danger") {
                                cmd = uri.query;
                                if (cmd.length > 100) {
                                    return;
                                } else {
                                    return;
                                }
                            }
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });
    });

    describe("Loop fixed-point analysis (T255561808)", () => {
        it("should report taint carried to a sink in a later for-of iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            for (const part of uri.query.split(",")) {
                                exec(command);
                                command += part;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should iterate until taint crosses multiple loop-carried assignments", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            let pending = "";
                            let next = "";
                            for (const part of uri.query.split(",")) {
                                exec(command);
                                command = pending;
                                pending = next;
                                next = part;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should analyze a for-loop incrementor after its body", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            for (let i = 0; i < 2; exec(command)) {
                                command = uri.query;
                                i++;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should report taint carried to a sink in a later while iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            while (Date.now() % 2 === 0) {
                                exec(command);
                                command = uri.query;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should report taint carried to a sink in a later do-while iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            do {
                                exec(command);
                                command = uri.query;
                            } while (Date.now() % 2 === 0);
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should report taint carried to a sink in a later for-in iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            for (const key in JSON.parse(uri.query)) {
                                exec(command);
                                command = key;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should report instance-field taint carried to a later iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Holder {
                    command = "";
                }

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const holder = new Holder();
                            while (Date.now() % 2 === 0) {
                                exec(holder.command);
                                holder.command = uri.query;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should carry field taint between iterations of an instance array", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Holder {
                    command = "";
                }

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const holder = new Holder();
                            const holders = [holder, holder];
                            for (const current of holders) {
                                exec(current.command);
                                current.command = uri.query;
                            }
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should preserve a tainted zero-iteration path after a while loop", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = uri.query;
                            while (Date.now() % 2 === 0) {
                                command = "fixed";
                            }
                            exec(command);
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should not preserve the pre-loop state for a mandatory do-while iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = uri.query;
                            do {
                                command = "fixed";
                            } while (Date.now() % 2 === 0);
                            exec(command);
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should preserve a tainted instance field on the zero-iteration path", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Holder {
                    constructor(public command: string) {}
                }

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const holder = new Holder(uri.query);
                            while (Date.now() % 2 === 0) {
                                holder.command = "fixed";
                            }
                            exec(holder.command);
                        }
                    });
                }
            `);

            expect(result.findings.some((finding) => finding.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should not report when every iteration clears taint before the sink", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let command = "";
                            for (const part of uri.query.split(",")) {
                                command = "fixed";
                                exec(command);
                                command += part;
                            }
                        }
                    });
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Clean reassignment (T268875722)", () => {
        it("should NOT report when a tainted variable is overwritten with a clean literal", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = uri.query;
                            cmd = "git status";
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should NOT report when a tainted variable is overwritten with a clean expression", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = uri.query;
                            cmd = "git " + "status";
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should NOT report when a tainted variable is overwritten with a sanitized value", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = uri.query;
                            cmd = String(Number(cmd));
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should still report when a tainted variable is reassigned with another tainted value", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = "safe";
                            cmd = uri.query;
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should still report taint via property access (obj.prop reassignment does not clear)", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const input = uri.query;
                            exec(input);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should NOT report when tainted variable is overwritten with a result of a clean function call", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function getDefaultCommand(): string {
                    return "echo hello";
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = uri.query;
                            cmd = getDefaultCommand();
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should report when taint flows through concatenation before reassignment", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = "safe";
                            cmd = "git clone " + uri.query;
                            exec(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should report when only one of multiple variables is cleared", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            let cmd = uri.query;
                            let other = uri.query;
                            cmd = "safe";
                            exec(other);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Constructor passthrough (T268875735)", () => {
        it("should propagate taint from constructor arguments to the constructed value", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const target = new URL(uri.query);
                            fetch(target);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("fetch"))).toBe(true);
        });

        it("should propagate constructor taint through receiver method calls", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const command = new String(uri.query);
                            exec(command.toString());
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });
    });

    describe("Constructor body modeling", () => {
        it("should preserve scoped numeric sanitization through constructor fields", async () => {
            const result = await analyzeSource(
                `
                import * as vscode from "vscode";

                class SafeRenderer {
                    private content: number;
                    constructor(raw: string) {
                        this.content = parseInt(raw, 10);
                    }
                    render(): number {
                        return this.content;
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const renderer = new SafeRenderer(uri.query);
                            const panel = vscode.window.createWebviewPanel("x", "x", vscode.ViewColumn.One);
                            panel.webview.html = "<p>" + renderer.render() + "</p>";
                        }
                    });
                }
            `,
                __dirname + "/typed-renderer-input.ts",
            );

            expect(result.findings.length).toBe(0);
        });

        it("should preserve taint when constructor assigns raw input to this.field (true positive)", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class CommandRunner {
                    private command: string;
                    constructor(cmd: string) {
                        this.command = cmd;
                    }
                    run() {
                        exec(this.command);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const runner = new CommandRunner(uri.query);
                            runner.run();
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("should detect taint when constructor concatenates raw input into this.field", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class CommandBuilder {
                    private cmd: string;
                    constructor(userInput: string) {
                        this.cmd = "echo " + userInput;
                    }
                    execute() {
                        exec(this.cmd);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const builder = new CommandBuilder(uri.query);
                            builder.execute();
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });
        it("should treat fs.readFile callback data as tainted", async () => {
            const result = await analyzeSource(`
                import * as fs from "fs";
                import { exec } from "child_process";

                export function activate() {
                    fs.readFile("config.json", (err, data) => {
                        exec(data.toString());
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "fs.readFile.data" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should treat fs.readFile callback data as tainted when the path is tainted", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import * as fs from "fs";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            fs.readFile(uri.query, (err, data) => {
                                exec(data.toString());
                            });
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "handleUri.uri" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should treat fs.readFile callback data as tainted when options are provided", async () => {
            const result = await analyzeSource(`
                import * as fs from "fs";
                import { exec } from "child_process";

                export function activate() {
                    fs.readFile("config.json", "utf8", (err, data) => {
                        exec(data);
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "fs.readFile.data" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should treat fs.readFile callback data as tainted in named callbacks", async () => {
            const result = await analyzeSource(`
                import * as fs from "fs";
                import { exec } from "child_process";

                export function activate() {
                    function onRead(err: Error | null, data: Buffer) {
                        exec(data.toString());
                    }
                    fs.readFile("config.json", onRead);
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "fs.readFile.data" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });

        it("should not treat the callback fs.readFile return value as file content", async () => {
            const result = await analyzeSource(`
                import * as fs from "fs";
                import { exec } from "child_process";

                export function activate() {
                    const data = fs.readFile("config.json", () => {});
                    exec(data);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should treat an awaited fs/promises.readFile result as file content", async () => {
            const result = await analyzeSource(`
                import { readFile } from "fs/promises";
                import { exec } from "child_process";

                export async function activate() {
                    const data = await readFile("config.json", "utf8");
                    exec(data);
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("fs.readFile");
        });

        it("should treat vscode.workspace.fs.readFile return values as tainted", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export async function activate() {
                    const data = await vscode.workspace.fs.readFile(vscode.Uri.file("config.json"));
                    exec(data.toString());
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some(
                    (f) => f.source.pattern === "vscode.workspace.fs.readFile" && f.sink.pattern.includes("exec"),
                ),
            ).toBe(true);
        });
    });

    describe("Generic callback parameter sources", () => {
        it("should support call-local callback parameter sources from a custom spec", async () => {
            const spec: TaintSpec = {
                entryFunctions: ["activate"],
                sources: [
                    {
                        kind: "parameter",
                        pattern: "custom.read.data",
                        description: "Custom callback data",
                        callbackRegistration: "readCustom",
                        callbackSource: "call",
                        callbackArgIndex: 0,
                        paramIndex: 0,
                    },
                ],
                sinks: [ExecSink],
                sanitizers: [],
            };

            const result = await analyzeSourceWithSpec(
                `
                import { exec } from "child_process";

                declare const source: {
                    readCustom(callback: (data: string) => void): void;
                };

                export function activate() {
                    source.readCustom((data) => {
                        exec(data);
                    });
                }
            `,
                spec,
            );

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(
                result.findings.some((f) => f.source.pattern === "custom.read.data" && f.sink.pattern.includes("exec")),
            ).toBe(true);
        });
    });

    describe("Multi-source passthrough (T255561777)", () => {
        it("should preserve all sources through unresolved function returns", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                declare function combine(first: string, second: string): string;

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const command = combine(uri.query, process.env.BUILD_CMD);
                            exec(command);
                        }
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings.length).toBe(2);
            expect(new Set(result.findings.map((f) => f.source.pattern))).toEqual(
                new Set(["handleUri.uri", "process.env"]),
            );
            expect(
                result.findings.every((f) =>
                    f.propagationChain.some((step) => step.description.includes("returned from combine()")),
                ),
            ).toBe(true);
        });

        it("should preserve all sources through unresolved constructors", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                declare const Command: {
                    new(first: string, second: string): { toString(): string };
                };

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const command = new Command(uri.query, process.env.BUILD_CMD);
                            exec(command.toString());
                        }
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(result.findings.length).toBe(2);
            expect(new Set(result.findings.map((f) => f.source.pattern))).toEqual(
                new Set(["handleUri.uri", "process.env"]),
            );
            expect(
                result.findings.every((f) =>
                    f.propagationChain.some((step) => step.description.includes("returned from new Command()")),
                ),
            ).toBe(true);
        });
    });

    describe("Memoization (T255561851)", () => {
        it("should hit the call cache when the same function is called twice with the same taint pattern", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runCommand(cmd: string) {
                    exec(cmd);
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const cmd = uri.query;
                            runCommand(cmd);
                            runCommand(cmd);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.cacheHits).toBeGreaterThanOrEqual(1);
        });

        it("should not hit cache when the same function is called with different taint provenance", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runCommand(cmd: string, label: string) {
                    exec(cmd);
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            runCommand(uri.query, "first");
                            runCommand(process.env.BUILD_CMD, "second");
                        }
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            // Same callee and argument position, but distinct source
            // provenance; the cache must not merge them.
            expect(result.cacheHits).toBe(0);
            expect(result.findings.length).toBe(2);
        });

        it("should not hit cache when different properties of the same source are passed to the same helper", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runCommand(cmd: string) {
                    exec(cmd);
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            runCommand(uri.query);
                            runCommand(uri.path);
                        }
                    });
                }
            `);

            // Different properties of one source require separate cache entries.
            // The finding-count assertion allows downstream deduplication; the
            // zero cache-hit assertion checks that both calls are analyzed.
            expect(result.cacheHits).toBe(0);
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should not suppress closure findings with different taint provenance", async () => {
            const result = await analyzeSourceWithSpec(
                `
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runLater(command: string) {
                    [1].forEach(() => {
                        exec(command);
                    });
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            runLater(uri.query);
                            runLater(process.env.BUILD_CMD);
                        }
                    });
                }
            `,
                vscodeSpecWithEnvSource,
            );

            expect(new Set(result.findings.map((f) => f.source.pattern))).toEqual(
                new Set(["process.env", "handleUri.uri"]),
            );
        });

        it("should not suppress findings from distinct entry points that share a helper", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                function runCommand(cmd: string) {
                    exec(cmd);
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            runCommand(uri.query);
                        }
                    });

                    const webview = createWebview();
                    webview.onDidReceiveMessage((message: {cmd: string}) => {
                        runCommand(message.cmd);
                    });
                }

                declare function createWebview(): any;
            `);

            expect(result.cacheHits).toBe(0);
            expect(result.findings.length).toBe(2);
            expect(new Set(result.findings.map((f) => f.source.pattern))).toEqual(
                new Set(["handleUri.uri", "onDidReceiveMessage.message"]),
            );
        });
    });

    describe("Rule tuning (T255562433)", () => {
        it("should NOT flag regex.exec as a command injection sink", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const pattern = /^[a-z]+$/;
                            pattern.exec(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
            expect(result.metrics.patternMatching.typeResolutionAttempts).toBeGreaterThan(0);
            expect(result.metrics.patternMatching.typeResolutionSuccesses).toBe(
                result.metrics.patternMatching.typeResolutionAttempts,
            );
            expect(result.metrics.patternMatching.heuristicFallbackAttempts).toBe(0);
            expect(result.metrics.patternMatching.heuristicFallbackMatches).toBe(0);
        });

        it("should keep fully resolved sink matching off the heuristic fallback path", async () => {
            const result = await analyzeSourceWithDebug(
                `
                import { exec } from "child_process";

                export function activate() {
                    const cmd = process.env.BUILD_CMD;
                    exec(cmd);
                }
            `,
                vscodeSpecWithEnvSource,
            );

            const metrics = result.metrics.patternMatching;
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(metrics.typeResolutionAttempts).toBeGreaterThan(0);
            const sinks =
                result.metrics.patternMatching.debugEntries?.filter((entry) => entry.context === "sink.callArgument") ??
                [];
            expect(sinks.length).toBeGreaterThan(0);
            expect(sinks.every((entry) => entry.strategy === "typeResolved")).toBe(true);
            expect(metrics.typeResolvedMatches).toBeGreaterThan(0);
        });

        it("should count heuristic fallback only when call type resolution is unavailable", async () => {
            const result = await analyzeSourceWithSpec(
                `
                export function activate() {
                    const cmd = process.env.BUILD_CMD;
                    exec(cmd);
                }
            `,
                vscodeSpecWithEnvSource,
            );

            const metrics = result.metrics.patternMatching;
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(metrics.typeResolutionAttempts).toBeGreaterThan(0);
            expect(metrics.typeResolutionSuccesses).toBeLessThan(metrics.typeResolutionAttempts);
            expect(metrics.heuristicFallbackAttempts).toBeGreaterThan(0);
            expect(metrics.heuristicFallbackMatches).toBeGreaterThan(0);
        });

        it("should only match call-return sources on call expressions", async () => {
            const result = await analyzeSourceWithDebug(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export async function activate() {
                    const input = await vscode.window.showInputBox();
                    exec(input!);
                }
            `);

            const entries = result.metrics.patternMatching.debugEntries ?? [];
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.source.pattern === "vscode.window.showInputBox")).toBe(true);
            expect(entries.some((entry) => entry.context === "source.callReturnValue")).toBe(true);
            expect(entries.some((entry) => entry.context === "source.callReturnValue.propertyAccessCheck")).toBe(false);
        });

        it("should still match property-access sources on property reads", async () => {
            const result = await analyzeSourceWithDebug(
                `
                import { exec } from "child_process";

                export function activate() {
                    const cmd = process.env.BUILD_CMD;
                    exec(cmd);
                }
            `,
                vscodeSpecWithEnvSource,
            );

            const entries = result.metrics.patternMatching.debugEntries ?? [];
            expect(result.findings.some((f) => f.source.pattern === "process.env")).toBe(true);
            expect(
                entries.some(
                    (entry) =>
                        entry.context === "source.propertyAccess.propertyAccessCheck" &&
                        entry.name === "process.env" &&
                        entry.pattern === "NodeJS.Process.env" &&
                        entry.matched,
                ),
            ).toBe(true);
        });

        it("should debug-match other VS Code call-return APIs only as call returns", async () => {
            const result = await analyzeSourceWithDebug(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                declare function getChoices(): string[];
                export async function activate() {
                    const selection = await vscode.window.showQuickPick(getChoices());
                    const clipboard = await vscode.env.clipboard.readText();
                    exec(selection!);
                    exec(clipboard);
                }
            `);

            const entries = result.metrics.patternMatching.debugEntries ?? [];
            const sourcePatterns = new Set(result.findings.map((f) => f.source.pattern));
            expect(sourcePatterns.has("vscode.window.showQuickPick")).toBe(true);
            expect(sourcePatterns.has("vscode.env.clipboard.readText")).toBe(true);
            for (const pattern of ["vscode.window.showQuickPick", "vscode.env.clipboard.readText"]) {
                expect(
                    entries.some(
                        (entry) =>
                            entry.context === "source.callReturnValue" && entry.pattern === pattern && entry.matched,
                    ),
                ).toBe(true);
                expect(
                    entries.some(
                        (entry) =>
                            entry.context === "source.callReturnValue.propertyAccessCheck" && entry.pattern === pattern,
                    ),
                ).toBe(false);
            }
        });

        it("should debug-match process.env as a property source through child properties", async () => {
            const result = await analyzeSourceWithDebug(
                `
                import { exec } from "child_process";

                export function activate() {
                    const env = process.env;
                    const cmd = env.BUILD_CMD;
                    exec(cmd);
                }
            `,
                vscodeSpecWithEnvSource,
            );

            const entries = result.metrics.patternMatching.debugEntries ?? [];
            expect(
                result.findings.some(
                    (f) =>
                        f.source.pattern === "process.env" &&
                        f.propagationChain.some((step) => step.description.includes("accessed property 'BUILD_CMD'")),
                ),
            ).toBe(true);
            expect(
                entries.some(
                    (entry) =>
                        entry.context === "source.propertyAccess.propertyAccessCheck" &&
                        entry.name === "process.env" &&
                        entry.pattern === "NodeJS.Process.env" &&
                        entry.matched,
                ),
            ).toBe(true);
        });

        it("should not treat process.env as a source in the VS Code spec", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";

                export function activate() {
                    const cmd = process.env.BUILD_CMD;
                    exec(cmd);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should detect taint flowing to vscode.env.openExternal", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const target = vscode.Uri.parse(uri.query);
                            vscode.env.openExternal(target);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("openExternal"))).toBe(true);
        });

        it("should detect taint flowing to fetch", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            fetch(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("fetch"))).toBe(true);
        });

        it("should detect taint flowing to http.request", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import * as http from "http";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            http.request(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("request"))).toBe(true);
        });

        it("should detect taint flowing to workspace.applyEdit", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            // Tainted data flows directly into applyEdit via
                            // conservative propagation through buildEdit()
                            const edit = buildEdit(uri.query);
                            vscode.workspace.applyEdit(edit);
                        }
                    });
                }

                function buildEdit(content: string) {
                    return content;
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("applyEdit"))).toBe(true);
        });
    });

    describe("Stable finding handles", () => {
        // Handles are source.pattern | sink.name | entryPointName |
        // sinkFileName | sinkLine. The line distinguishes repeated occurrences
        // of the same source/sink pair in one file.
        it("should produce handles with structural identity and line tiebreaker", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";
                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            exec(uri.query);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(1);
            expect(result.findings[0].handle).toBe(
                "handleUri.uri|exec|URI handler (vscode:// deeplink)|/src/extension.ts|7",
            );
        });

        it("should produce different handles for same pattern at different locations in same file", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";
                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            exec(uri.query);
                            exec(uri.path);
                        }
                    });
                }
            `);

            // Both exec calls should produce findings with different handles
            // (different line numbers as tiebreaker)
            expect(result.findings.length).toBe(2);
            expect(result.findings[0].handle).not.toBe(result.findings[1].handle);
        });

        it("handle should include sink name", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";
                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) { exec(uri.query); }
                    });
                }
            `);

            expect(result.findings[0].handle).toContain(`|${ExecSink.name}|`);
        });
    });

    describe("No false positives", () => {
        it("should not report hardcoded command strings", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";

                export function activate() {
                    exec("git status");
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should not report when no source is present", async () => {
            const result = await analyzeSource(`
                import { exec } from "child_process";

                function doSomething() {
                    const cmd = "ls -la";
                    exec(cmd);
                }
            `);

            expect(result.findings.length).toBe(0);
        });
    });

    describe("Inherited constructor field state", () => {
        it("should propagate taint through an explicit super call", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class BaseRunner {
                    constructor(protected command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                class Runner extends BaseRunner {
                    constructor(command: string) {
                        super(command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const runner = new Runner(command!);
                    runner.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve base-constructor sanitization through an explicit super call", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class BaseRunner {
                    protected command: string;
                    constructor(command: string) {
                        this.command = String(Number(command));
                    }
                    run() {
                        exec(this.command);
                    }
                }

                class Runner extends BaseRunner {
                    constructor(command: string) {
                        super(command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const runner = new Runner(command!);
                    runner.run();
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Override dispatch for body-less methods (T272262006)", () => {
        it("follows an abstract method called through this into subclass overrides", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                abstract class Scanner {
                    abstract scan(path: string): Promise<string>;
                    async scanCached(path: string): Promise<string> {
                        return this.scan(path);
                    }
                }

                class FixedScanner extends Scanner {
                    async scan(path: string) { return path; }
                }

                class ToolScanner extends Scanner {
                    async scan(path: string) {
                        const tool = vscode.workspace.getConfiguration().get<string>("demo.toolPath");
                        exec(\`\${tool} \${path}\`);
                        return "";
                    }
                }

                class Provider {
                    constructor(private scanner: Scanner) {}
                    refresh(path: string) { return this.scanner.scanCached(path); }
                }

                export function activate() {
                    for (const scanner of [new FixedScanner(), new ToolScanner()]) {
                        void new Provider(scanner).refresh("/tmp/file");
                    }
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("WorkspaceConfiguration.get");
            expect(result.findings[0].sink.name).toBe("exec");
        });

        it("passes argument taint to interface implementations", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                interface Runner { run(command: string): void; }
                class ShellRunner implements Runner { run(command: string) { exec(command); } }
                class LogRunner implements Runner { run(command: string) { console.log(command); } }

                function execute(runner: Runner, command: string) { runner.run(command); }

                export function activate() {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) { execute(new ShellRunner(), uri.query); },
                    });
                }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("handleUri.uri");
        });

        it("returns override taint to the calling base-class method", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                abstract class Tool {
                    abstract path(): string;
                    run() { exec(\`\${this.path()} --version\`); }
                }

                class ConfiguredTool extends Tool {
                    path() { return vscode.workspace.getConfiguration().get<string>("demo.toolPath") ?? "tool"; }
                }

                export function activate() { new ConfiguredTool().run(); }
            `);

            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("WorkspaceConfiguration.get");
        });

        it("follows overrides through an intermediate abstract class", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                abstract class Base {
                    abstract run(command: string): void;
                    start(command: string) { this.run(command); }
                }
                abstract class Named extends Base { label() { return "shell"; } }
                class Shell extends Named { run(command: string) { exec(command); } }

                export function activate(base: Base) {
                    base.start(vscode.workspace.getConfiguration().get<string>("demo.command")!);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("keeps argument passthrough when the overrides return clean values", async () => {
            // The receiver is unknown: implementations outside the program can satisfy the type.
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                interface Formatter { format(value: string): string; }
                class FixedFormatter implements Formatter { format(value: string) { return "fixed"; } }

                function render(formatter: Formatter, value: string) { exec(formatter.format(value)); }

                export function activate(formatter: Formatter) {
                    render(formatter, vscode.workspace.getConfiguration().get<string>("demo.value")!);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("does not expand methods declared in declaration files", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Deferred implements PromiseLike<string> {
                    then(): any {
                        exec(vscode.workspace.getConfiguration().get<string>("demo.command")!);
                        return this;
                    }
                }

                function settle(value: PromiseLike<string>) { value.then(); }

                export function activate(value: PromiseLike<string>) { settle(value); }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("falls back to passthrough above the candidate cap", async () => {
            const clean = Array.from(
                { length: 8 },
                (_, i) => `class Clean${i} implements Runner { run(command: string) {} }`,
            ).join("\n");
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                interface Runner { run(command: string): void; }
                class ShellRunner implements Runner { run(command: string) { exec(command); } }
                ${clean}

                export function activate(runner: Runner) {
                    runner.run(vscode.workspace.getConfiguration().get<string>("demo.command")!);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Constructor helper field state", () => {
        it("should preserve tainted field writes made by aliased constructor helpers", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    private command = "fixed";
                    constructor(command: string) {
                        const self = this;
                        const alias = self;
                        alias.setCommand(command);
                    }
                    private setCommand(command: string) {
                        this.command = command;
                    }
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const runner = new Runner(command!);
                    runner.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve clean field writes made by constructor helpers", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    private command: string;
                    constructor(command: string) {
                        this.command = command;
                        this.clearCommand();
                    }
                    private clearCommand() {
                        this.command = "fixed";
                    }
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const runner = new Runner(command!);
                    runner.run();
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Constructor field state per-instance isolation", () => {
        it("should NOT merge field state between different instances (tainted a, clean b — b.field not tainted)", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    command: string;
                    constructor(cmd: string) {
                        this.command = cmd;
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const a = new Runner(uri.query);
                            const b = new Runner("safe-hardcoded");
                            exec(b.command);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should report when tainted instance field reaches sink (a.field tainted)", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    command: string;
                    constructor(cmd: string) {
                        this.command = cmd;
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const a = new Runner(uri.query);
                            const b = new Runner("safe-hardcoded");
                            exec(a.command);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should isolate field state when both instances exist but only one is tainted", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Config {
                    value: string;
                    constructor(v: string) {
                        this.value = v;
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const tainted = new Config(uri.query);
                            const clean = new Config("literal");
                            exec(tainted.value);
                            exec(clean.value);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(1);
        });

        it("should track field state through a nested instance", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Backend {
                    private command: string;
                    constructor(command: string) {
                        this.command = command;
                    }
                    run() {
                        exec(this.command);
                    }
                }

                class Controller {
                    constructor(private backend: Backend) {}
                    run() {
                        const self = this;
                        self.backend.run();
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const controller = new Controller(new Backend(command!));
                    controller.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should isolate field state between nested instances", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Backend {
                    private command: string;
                    constructor(command: string) {
                        this.command = command;
                    }
                    run() {
                        exec(this.command);
                    }
                }

                class Controller {
                    private backend: Backend;
                    constructor(backend: Backend) {
                        this.backend = backend;
                    }
                    run() {
                        this.backend.run();
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const tainted = new Controller(new Backend(command!));
                    const clean = new Controller(new Backend("fixed"));
                    const alias = tainted;
                    alias.run();
                    clean.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should track scalar constructor parameter properties", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const runner = new Runner(command!);
                    runner.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should update nested fields without merging instances", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Backend {
                    command = "fixed";
                    run() {
                        exec(this.command);
                    }
                }

                class Controller {
                    constructor(private backend: Backend) {}
                    setCommand(command: string) {
                        this.backend.command = command;
                    }
                    run() {
                        this.backend.run();
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const tainted = new Controller(new Backend());
                    const clean = new Controller(new Backend());
                    tainted.setCommand(command!);
                    clean.setCommand(command!);
                    clean.setCommand("fixed");
                    tainted.run();
                    clean.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should isolate constructor-less instances", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    command = "fixed";
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const tainted = new Runner();
                    const clean = new Runner();
                    tainted.command = command!;
                    tainted.run();
                    clean.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });
    });

    describe("Constructor sanitizer field state", () => {
        it("should clear field taint when constructor sanitizes input", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class SafeRunner {
                    command: string;
                    constructor(cmd: string) {
                        this.command = String(Number(cmd));
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const runner = new SafeRunner(uri.query);
                            exec(runner.command);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });

        it("should preserve field taint when constructor does raw assignment", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class UnsafeRunner {
                    command: string;
                    constructor(cmd: string) {
                        this.command = cmd;
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const runner = new UnsafeRunner(uri.query);
                            exec(runner.command);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Returned instance state", () => {
        it("should preserve instance fields returned from a factory", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                function makeRunner(command: string) {
                    return new Runner(command);
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    makeRunner(command!).run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve clean fields on a returned instance", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    command: string;
                    constructor(command: string) {
                        this.command = String(Number(command));
                    }
                }

                function makeRunner(command: string) {
                    return new Runner(command);
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command");
                    const runner = makeRunner(command!);
                    exec(runner.command);
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should not share mutable state between factory results", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    clear() {
                        this.command = "fixed";
                    }
                    run() {
                        exec(this.command);
                    }
                }

                function makeRunner(command: string) {
                    return new Runner(command);
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const tainted = makeRunner(command);
                    const clean = makeRunner(command);
                    clean.clear();
                    tainted.run();
                    clean.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should conservatively merge instances from multiple return sites", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                function makeRunner(command: string, useCommand: boolean) {
                    if (useCommand) {
                        return new Runner(command);
                    }
                    return new Runner("fixed");
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    makeRunner(command, Math.random() > 0.5).run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });
    });

    describe("Container instance state", () => {
        it("should read a tainted instance at a literal array index", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const runners = [new Runner(command), new Runner("fixed")];
                    runners[0].run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve a clean instance at a different array index", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const runners = [new Runner(command), new Runner("fixed")];
                    runners[1].run();
                }
            `);

            expect(result.findings).toHaveLength(0);
        });

        it("should conservatively merge instances for dynamic array access", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const runners = [new Runner(command), new Runner("fixed")];
                    const index = Math.random() > 0.5 ? 0 : 1;
                    runners[index].run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve instances through array destructuring", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const [runner] = [new Runner(command)];
                    runner.run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should preserve instances through array iteration", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    for (const runner of [new Runner(command)]) {
                        runner.run();
                    }
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should track instances added by push", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const runners: Runner[] = [];
                    runners.push(new Runner(command));
                    runners[0].run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should track instances added by element assignment", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Runner {
                    constructor(private command: string) {}
                    run() {
                        exec(this.command);
                    }
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const runners: Runner[] = [];
                    runners[0] = new Runner(command);
                    runners[0].run();
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should propagate element taint through forEach into a returned array", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { spawn } from "child_process";

                function buildArgs(values: string[]): string[] {
                    const args: string[] = [];
                    values.forEach((value) => args.push(value));
                    return args;
                }

                export function activate() {
                    const command = vscode.workspace.getConfiguration().get<string>("command")!;
                    const args = buildArgs([command]);
                    spawn("fixed", args);
                }
            `);

            expect(result.findings).toHaveLength(1);
        });

        it("should not taint returned array elements from control-only inputs", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { spawn } from "child_process";

                function selectValues(setting: string): string[] {
                    const result: string[] = [];
                    for (const value of ["fixed"]) {
                        if (setting !== "disabled") {
                            result.push(value);
                        }
                    }
                    return result;
                }

                export function activate() {
                    const setting = vscode.workspace.getConfiguration().get<string>("setting")!;
                    spawn("fixed", selectValues(setting));
                }
            `);

            expect(result.findings).toHaveLength(0);
        });
    });

    describe("const self = this alias", () => {
        it("should track taint through self.field writes when self = this", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Handler {
                    cmd: string = "";
                    configure(input: string) {
                        const self = this;
                        self.cmd = input;
                    }
                    run() {
                        exec(this.cmd);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const h = new Handler();
                            h.configure(uri.query);
                            h.run();
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("should track taint through self.field reads when self = this", async () => {
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                class Executor {
                    command: string;
                    constructor(cmd: string) {
                        this.command = cmd;
                    }
                    execute() {
                        const self = this;
                        exec(self.command);
                    }
                }

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const e = new Executor(uri.query);
                            e.execute();
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe("Deep expression flattening", () => {
        it("propagates taint through a deeply nested string concatenation", async () => {
            // A long left-associative concatenation (the codetrust getScript()
            // webview-HTML pattern). Without iterative flattening, analyzing
            // this recurses once per operand and risks exhausting the call
            // stack; the tainted operand must still reach the sink.
            const literals = new Array(4000).fill('"x"').join(" + ");
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const tainted = uri.query;
                            const html = ${literals} + tainted;
                            exec(html);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });

        it("does not taint a deep concatenation of only clean literals", async () => {
            const literals = new Array(4000).fill('"x"').join(" + ");
            const result = await analyzeSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                export function activate(context: vscode.ExtensionContext) {
                    vscode.window.registerUriHandler({
                        handleUri(uri: vscode.Uri) {
                            const html = ${literals};
                            exec(html);
                        }
                    });
                }
            `);

            expect(result.findings.length).toBe(0);
        });
    });
});
