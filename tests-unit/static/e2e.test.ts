/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyze, AnalyzerResult } from "../../src/static/analyzer";
import { writeFindingsSappStream, writeTraceFramesSappStream } from "../../src/static/sappFormatter";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { expressSpec } from "../../src/static/spec/express";
import { analyzeFixture, FIXTURES } from "./testUtils";

/**
 * Read the small fixture output through the same streaming writers used by
 * the CLI, then remove the final newline for assertions. Production streams
 * each record to avoid building one string for the entire bundle.
 */
function readSappNdjson(result: AnalyzerResult, fileName: string, write: typeof writeFindingsSappStream): string {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-test-"));
    const outputPath = path.join(tmp, fileName);
    try {
        write(outputPath, result.findings, result.sappRepoRoot);
        return fs.readFileSync(outputPath, "utf-8").replace(/\n$/, "");
    } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
}

function readSappIssuesNdjson(result: AnalyzerResult): string {
    return readSappNdjson(result, "issues.ndjson", writeFindingsSappStream);
}

function readSappTraceFramesNdjson(result: AnalyzerResult): string {
    return readSappNdjson(result, "traceFrames.ndjson", writeTraceFramesSappStream);
}

describe("E2E: Deeplink RCE Detection (projectDir)", () => {
    describe("Vulnerable fixtures", () => {
        it("uri-handler-rce: detects direct uri.query → exec flow", async () => {
            const result = await analyzeFixture("uri-handler-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("exec-injection: detects string concat into exec", async () => {
            const result = await analyzeFixture("exec-injection");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("template-literal-injection: detects template literal into exec", async () => {
            const result = await analyzeFixture("template-literal-injection");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("interprocedural-injection: detects taint through helper function", async () => {
            const result = await analyzeFixture("interprocedural-injection");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("class-uri-handler-terminal: detects class URI handler → this.method → terminal.sendText (D74929992)", async () => {
            const result = await analyzeFixture("class-uri-handler-terminal");
            expect(result.findings.length).toBe(1);
            expect(
                result.findings.some((f) => f.sink.pattern.includes("sendText") || f.sink.pattern.includes("Terminal")),
            ).toBe(true);
        });

        it("imported-class-uri-handler-rce: detects imported URI handler class instantiated inline → debug.startDebugging (D95145147)", async () => {
            const result = await analyzeFixture("imported-class-uri-handler-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings[0].source.description).toContain("URI handler");
            expect(result.findings[0].sink.pattern).toContain("startDebugging");
        });

        it("command-handler-multi-arg-rce: detects taint from a non-zero command handler parameter → spawn", async () => {
            const result = await analyzeFixture("command-handler-multi-arg-rce");
            // These are separate sink categories: control of the binary is
            // rce, while control of argv is arg_injection. This fixture taints
            // both; the assertions do not establish that the binary is fixed.
            expect(result.findings.length).toBe(2);
            expect(result.findings.every((f) => f.sink.pattern.includes("spawn"))).toBe(true);
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
            expect(result.findings.some((f) => f.sink.categories.includes("arg_injection"))).toBe(true);
        });

        it("debug-config-property-sink: reports execution-bearing config fields and skips the cosmetic name", async () => {
            const result = await analyzeFixture("debug-config-property-sink");
            const dbg = result.findings.filter((f) => f.sink.name === "startDebugging");
            // initCommands, program, connect, and the whole-config case — but
            // NOT the handler that only taints the session `name`.
            expect(dbg).toHaveLength(4);
            expect(dbg.every((f) => !f.sinkLocation.text?.includes("Session"))).toBe(true);
        });

        it("document-content-rce: detects open text passed to a shell sink", async () => {
            const result = await analyzeFixture("document-content-rce");
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("TextDocument.getText");
            expect(result.findings[0].sink.name).toBe("exec");
            expect(result.findings[0].sink.categories).toContain("rce");
        });

        it("filename-source-rce: treats directory listings as tainted and reaches spawn with shell:true", async () => {
            const result = await analyzeFixture("filename-source-rce");
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
            expect(result.findings.some((f) => f.source.description.includes("Directory listing"))).toBe(true);
            // shell:true makes this command execution, not mere arg injection.
            expect(result.findings.some((f) => f.sink.categories.includes("rce"))).toBe(true);
        });

        it("file-write-path: distinguishes path control from content persistence (T288945940)", async () => {
            const result = await analyzeFixture("file-write-path");
            expect([...new Set(result.findings.map((f) => f.sink.name))].sort()).toEqual([
                "vscode_writeFile_path",
                "writeFileSync",
                "writeFileSync_path",
                "writeFile_path",
            ]);
            const content = result.findings.filter((f) => f.sink.name === "writeFileSync");
            expect(content).toHaveLength(1);
            expect(content[0].sink.categories).toEqual(["file_integrity"]);
            expect(content[0].sink.severity).toBe("low");
        });

        it("void-expression-sink: traverses the operand of a `void` expression", async () => {
            const result = await analyzeFixture("void-expression-sink");
            // One finding is the void path under test; the awaited path is
            // the control.
            expect(result.findings.length).toBe(2);
            expect(result.findings.every((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("multi-file-rce: detects taint across 4 files (extension → uriHandler → commandRunner → terminal)", async () => {
            const result = await analyzeFixture("multi-file-rce");
            expect(result.findings.length).toBe(1);
            expect(
                result.findings.some((f) => f.sink.pattern.includes("sendText") || f.sink.pattern.includes("Terminal")),
            ).toBe(true);
            const finding = result.findings[0];
            const filesInChain = new Set<string>();
            filesInChain.add(path.basename(finding.sourceLocation.fileName));
            filesInChain.add(path.basename(finding.sinkLocation.fileName));
            for (const step of finding.propagationChain) {
                filesInChain.add(path.basename(step.location.fileName));
            }
            expect(filesInChain.size).toBeGreaterThanOrEqual(2);
        });

        it("spread-object-helper-rce: resolves a helper through a spread object and a cast object literal", async () => {
            const result = await analyzeFixture("spread-object-helper-rce");
            expect(result.findings.map((f) => [f.sink.name, path.basename(f.sinkLocation.fileName)])).toEqual([
                ["execFile_args", "helpers.ts"],
            ]);
        });

        it("executecommand-bridge-rce: detects taint flowing through executeCommand → registerCommand bridge (D74929992)", async () => {
            const result = await analyzeFixture("executecommand-bridge-rce");
            expect(result.findings.length).toBe(1);
            expect(
                result.findings.some((f) => f.sink.pattern.includes("sendText") || f.sink.pattern.includes("Terminal")),
            ).toBe(true);
        });

        it("deeplink-assistant-rce: detects AI assistant deeplink params → executeCommand bridge → terminal (D86095152)", async () => {
            const result = await analyzeFixture("deeplink-assistant-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.source.description.includes("URI handler"))).toBe(true);
            expect(
                result.findings.some((f) => f.sink.pattern.includes("sendText") || f.sink.pattern.includes("Terminal")),
            ).toBe(true);
        });

        it("deeplink-prompt-rce: detects AI assistant deeplink prompt → exec (D75979307)", async () => {
            const result = await analyzeFixture("deeplink-prompt-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("deeplink-fragment-injection: detects deeplink uri.fragment → string concat → terminal (D53663037)", async () => {
            const result = await analyzeFixture("deeplink-fragment-injection");
            expect(result.findings.length).toBe(1);
            expect(
                result.findings.some((f) => f.sink.pattern.includes("sendText") || f.sink.pattern.includes("Terminal")),
            ).toBe(true);
        });

        it("workspace-config-rce: detects workspace config → execFile", async () => {
            const result = await analyzeFixture("workspace-config-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("execFile"))).toBe(true);
        });

        it("promisified-exec-rce: detects workspace config → promisify(exec) exported from another module (T293393476)", async () => {
            const result = await analyzeFixture("promisified-exec-rce");
            expect(result.findings).toHaveLength(1);
            const finding = result.findings[0];
            expect(finding.source.pattern).toBe("WorkspaceConfiguration.get");
            expect(finding.sink.name).toBe("exec");
            expect(finding.promisified).toBe(true);
            expect(path.basename(finding.sinkLocation.fileName)).toBe("loader.ts");
        });

        it("abstract-dispatch-rce: detects workspace config → exec in an override of an abstract method (T293409641)", async () => {
            const result = await analyzeFixture("abstract-dispatch-rce");
            expect(result.findings).toHaveLength(1);
            const finding = result.findings[0];
            expect(finding.source.pattern).toBe("WorkspaceConfiguration.get");
            expect(finding.sink.name).toBe("exec");
            expect(path.basename(finding.sinkLocation.fileName)).toBe("tool.ts");
        });

        it("workspace-command-output-rce: detects names printed by a CLI run in the workspace → exec", async () => {
            const result = await analyzeFixture("workspace-command-output-rce");
            expect(result.findings).toHaveLength(1);
            const finding = result.findings[0];
            expect(finding.source.pattern).toBe("child_process.exec");
            expect(finding.sourceLocation.line).toBe(29);
            expect(finding.sink.name).toBe("exec");
            expect(finding.sinkLocation.line).toBe(35);
        });

        it("codelens-provider-rce: detects workspace config → exec reached only from provideCodeLenses (T293409641)", async () => {
            const result = await analyzeFixture("codelens-provider-rce");
            expect(result.findings).toHaveLength(1);
            const finding = result.findings[0];
            expect(finding.source.pattern).toBe("WorkspaceConfiguration.get");
            expect(finding.sink.name).toBe("exec");
            expect(path.basename(finding.sinkLocation.fileName)).toBe("tool.ts");
        });

        it("handler-property-rce: analyzes handlers declared as function-valued properties", async () => {
            const result = await analyzeFixture("handler-property-rce");
            expect(
                result.findings.map((f) => `${f.source.pattern} → ${f.sink.name}:${f.sinkLocation.line}`).sort(),
            ).toEqual([
                "WorkspaceConfiguration.get → spawn:32",
                "createDebugAdapterDescriptor.session → spawn:39",
                "handleUri.uri → exec:25",
            ]);
        });

        describe("config-closure-arrow-rce: workspace config through arrow consts, defaults, parameter properties, and stored closures", () => {
            let result: AnalyzerResult;
            beforeAll(async () => {
                result = await analyzeFixture("config-closure-arrow-rce");
            });

            function sinkAt(text: string) {
                return result.findings.filter(
                    (f) => f.source.pattern === "WorkspaceConfiguration.get" && f.sinkLocation.text === text,
                );
            }

            it("reports each sink once", () => {
                expect(result.findings).toHaveLength(6);
            });

            it("control: function declaration → execFile", () => {
                expect(sinkAt("execFile(ctlPath, args)")).toHaveLength(1);
            });

            it("A: exported const arrow function → spawn", () => {
                expect(sinkAt("spawn(ctlPath, args)")).toHaveLength(1);
            });

            it("B: default-parameter callee → execFile", () => {
                expect(sinkAt("execFile(file, args)")).toHaveLength(1);
            });

            it("C: renamed property read through a constructor parameter property → spawn", () => {
                expect(sinkAt('spawn(options.executable, ["embed"])')).toHaveLength(1);
            });

            it("D1: closure stored in a field, called and destructured → execFile", () => {
                expect(sinkAt('execFile(ctlPath, ["node", "list"])')).toHaveLength(1);
            });

            it("D2: field of a helper-built union → execFile", () => {
                expect(sinkAt('execFile(m.ctlPath, ["node", "exec", "--", "sh", "-c", "ls"])')).toHaveLength(1);
            });
        });

        it("workspace-config-object-rce: detects nested workspace config → exec (T285625899)", async () => {
            const result = await analyzeFixture("workspace-config-object-rce");
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("WorkspaceConfiguration.get");
            expect(result.findings[0].sink.pattern).toBe("child_process.exec");
        });

        it("language-client-shell-rce: detects workspace setting → language server argv with shell:true (T271372254)", async () => {
            const result = await analyzeFixture("language-client-shell-rce");
            expect(result.findings).toHaveLength(1);
            const finding = result.findings[0];
            expect(finding.source.pattern).toBe("WorkspaceConfiguration.get");
            expect(path.basename(finding.sourceLocation.fileName)).toBe("extension.ts");
            expect(finding.sink.name).toBe("LanguageClient_args");
            expect(finding.sink.categories).toEqual(["rce"]);
            expect(finding.sink.severity).toBe("critical");
            expect(path.basename(finding.sinkLocation.fileName)).toBe("languageClient.ts");
            expect(finding.sinkLocation.text).toBe("super(id, name, serverOptions, clientOptions, forceDebug)");
            expect(
                finding.propagationChain.some(
                    (step) =>
                        step.kind === "objectProperty" &&
                        step.description === "args" &&
                        path.basename(step.location.fileName) === "client.ts",
                ),
            ).toBe(true);
        });

        it("setting-scope-source: labels settings with the scope package.json declares", async () => {
            const result = await analyzeFixture("setting-scope-source");
            const source = vscodeExtensionSpec.sources.find((s) => s.pattern === "WorkspaceConfiguration.get")!;
            const workspace = source.description;
            const machine = source.settingScopeDescriptions!.machine;
            const application = source.settingScopeDescriptions!.application;
            const labels = Object.fromEntries(
                result.findings.map((f) => [
                    /\["([a-z-]+)"\]\)$/.exec(f.sinkLocation.text ?? "")?.[1],
                    f.source.description,
                ]),
            );
            expect(result.findings.every((f) => f.source.pattern === "WorkspaceConfiguration.get")).toBe(true);
            expect(labels).toEqual({
                machine: machine,
                application: application,
                window: workspace,
                "full-key": machine,
                "object-property": machine,
                destructured: machine,
                "whole-object": workspace,
                "dynamic-key": workspace,
            });
        });

        it("untyped-node-module-rce: matches cp.exec by its import when @types/node is missing (T293409590)", async () => {
            const result = await analyzeFixture("untyped-node-module-rce");
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].source.pattern).toBe("WorkspaceConfiguration.get");
            expect(result.findings[0].sink.pattern).toBe("child_process.exec");
        });

        it("deeplink-debug-config-rce: detects deeplink → debug config → startDebugging (D53746551)", async () => {
            const result = await analyzeFixture("deeplink-debug-config-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("startDebugging"))).toBe(true);
        });

        it("http-server-rce: detects HTTP server request → exec", async () => {
            const result = await analyzeFixture("http-server-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("websocket-server-rce: detects WebSocket message → executeCommand (T263572887)", async () => {
            const result = await analyzeFixture("websocket-server-rce");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("executeCommand"))).toBe(true);
        });
    });

    describe("Sanitizer fixtures", () => {
        it("shell-quote-sanitizer: distinguishes fixed arguments from commands (T255562430)", async () => {
            const result = await analyzeFixture("shell-quote-sanitizer");
            // Quoting the whole command and passing quoted data as `sh -c`
            // code remain command execution; a quoted argument after fixed
            // `agent` is reported as argument injection.
            expect(result.findings).toHaveLength(3);
            expect(result.findings.map((f) => f.sink.categories[0]).sort()).toEqual(["arg_injection", "rce", "rce"]);
            expect(result.findings.every((f) => f.sink.name === "sendText")).toBe(true);

            const sapp = await analyzeFixture("shell-quote-sanitizer", { outputFormat: "sapp-json" });
            const features = readSappIssuesNdjson(sapp)
                .split("\n")
                .flatMap((line) => JSON.parse(line).features as string[]);
            expect(features).toContain("prophecy-quoted-argument-to:agent");
        });
    });

    describe("Safe fixtures", () => {
        it("sanitized-input: no findings after numeric conversion", async () => {
            const result = await analyzeFixture("sanitized-input");
            expect(result.findings.length).toBe(0);
        });

        it("clean-uri-handler: allowlist guard is not yet modeled (known FP)", async () => {
            // The analyzer does not yet track control-flow sanitizers like
            // `if (allowlist.includes(x))`. This is a known false positive.
            const result = await analyzeFixture("clean-uri-handler");
            expect(result.findings.length).toBe(1);
        });
    });

    describe("package.json entry point discovery", () => {
        it("package-json-entry: discovers entry points from package.json main field", async () => {
            const result = await analyzeFixture("package-json-entry");
            expect(result.findings.length).toBe(1);
            expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
        });

        it("entryPointFilter: does not re-enable fallback entry points", async () => {
            const result = await analyze({
                projectDir: path.join(FIXTURES, "uri-handler-rce"),
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "text",
                entryPointFilter: ["not-a-real-entry-point"],
            });

            expect(result.entryPointCount).toBe(0);
            expect(result.findings).toHaveLength(0);
        });
    });

    describe("Report formatting", () => {
        it("uri-handler-rce: exposes pattern matching metrics", async () => {
            const result = await analyzeFixture("uri-handler-rce");
            const metrics = result.metrics.patternMatching;

            expect(metrics.typeResolutionAttempts).toBeGreaterThan(0);
            expect(metrics.typeResolutionSuccesses).toBeGreaterThan(0);
            expect(
                metrics.typeResolvedMatches + metrics.heuristicFallbackMatches + metrics.heuristicOnlyMatches,
            ).toBeGreaterThan(0);
        });

        it("uri-handler-rce: formattedOutput contains expected report structure", async () => {
            const result = await analyzeFixture("uri-handler-rce");
            expect(result.formattedOutput).toContain("CRITICAL");
            expect(result.formattedOutput).toContain("exec");
            expect(result.formattedOutput).toContain("extension.ts");
            expect(result.formattedOutput).toContain("Source:");
            expect(result.formattedOutput).toContain("Sink:");
        });

        it("sanitized-input: formattedOutput reports no findings", async () => {
            const result = await analyzeFixture("sanitized-input");
            expect(result.formattedOutput).toBe("No taint flows detected.");
        });
    });

    describe("JSON output", () => {
        it("uri-handler-rce: produces valid JSON with expected finding fields", async () => {
            const result = await analyze({
                projectDir: path.join(FIXTURES, "uri-handler-rce"),
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "json",
            });
            const parsed = JSON.parse(result.formattedOutput);
            expect(Array.isArray(parsed)).toBe(true);
            expect(parsed.length).toBe(1);
            for (const finding of parsed) {
                expect(finding).toHaveProperty("handle");
                expect(finding).toHaveProperty("source");
                expect(finding).toHaveProperty("sourceLocation");
                expect(finding).toHaveProperty("sink");
                expect(finding).toHaveProperty("sinkLocation");
                expect(finding).toHaveProperty("propagationChain");
                expect(finding.sourceLocation).toHaveProperty("fileName");
                expect(finding.sourceLocation).toHaveProperty("line");
                expect(finding.sourceLocation).toHaveProperty("column");
                expect(finding.sinkLocation).toHaveProperty("fileName");
                expect(finding.sinkLocation).toHaveProperty("line");
                expect(finding.sinkLocation).toHaveProperty("column");
                expect(Array.isArray(finding.propagationChain)).toBe(true);
            }
        });

        it("sanitized-input: JSON output is empty findings array", async () => {
            const result = await analyze({
                projectDir: path.join(FIXTURES, "sanitized-input"),
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "json",
            });
            const parsed = JSON.parse(result.formattedOutput);
            expect(Array.isArray(parsed)).toBe(true);
            expect(parsed.length).toBe(0);
        });
    });

    describe("Mermaid output", () => {
        it("uri-handler-rce: produces mermaid flowchart", async () => {
            const result = await analyze({
                projectDir: path.join(FIXTURES, "uri-handler-rce"),
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "mermaid",
            });
            expect(result.formattedOutput).toContain("```mermaid");
            expect(result.formattedOutput).toContain("flowchart TD");
            expect(result.formattedOutput).toContain("Source:");
            expect(result.formattedOutput).toContain("Sink:");
            expect(result.formattedOutput).toContain("extension.ts:");
        });

        it("sanitized-input: mermaid reports no findings", async () => {
            const result = await analyze({
                projectDir: path.join(FIXTURES, "sanitized-input"),
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "mermaid",
            });
            expect(result.formattedOutput).toBe("No taint flows detected.");
        });
    });
});

describe("E2E: SAPP JSON output format", () => {
    function analyzeSappFixture(name: string) {
        return analyzeFixture(name, {
            outputFormat: "sapp-json",
        });
    }

    it("uri-handler-rce: produces valid NDJSON with expected SAPP fields", async () => {
        const result = await analyzeSappFixture("uri-handler-rce");
        const lines = readSappIssuesNdjson(result).trim().split("\n");
        expect(lines.length).toBe(1);

        const issue = JSON.parse(lines[0]);
        expect(issue.kind).toBe("issue");
        expect(issue.code).toBe(9001); // RCE
        expect(typeof issue.handle).toBe("string");
        expect(issue.handle.length).toBeGreaterThan(0);
        expect(issue.handle.length).toBeLessThanOrEqual(255);
        expect(issue.callable).toBeDefined();
        expect(issue.callable).toContain("::");
        expect(issue.callable_line).toBeGreaterThan(0);
        expect(issue.filename).toBeDefined();
        expect(issue.position).toBeDefined();
        expect(issue.position.line).toBeGreaterThan(0);
        expect(issue.position.start).toBeGreaterThanOrEqual(0);
        expect(issue.position.end).toBeGreaterThan(issue.position.start);
        expect(issue.description).toContain("source(s) may reach");
        expect(issue.description).toContain("sink(s)");
        expect(Array.isArray(issue.traces)).toBe(true);
        expect(issue.traces.length).toBe(2);
        expect(Array.isArray(issue.features)).toBe(true);
    });

    it("uri-handler-rce: traces have correct forward/backward structure", async () => {
        const result = await analyzeSappFixture("uri-handler-rce");
        const issue = JSON.parse(readSappIssuesNdjson(result).trim().split("\n")[0]);

        // SAPP represents the source side as forward and the sink side as
        // backward.
        const forward = issue.traces.find((t: any) => t.forward);
        expect(forward).toBeDefined();
        expect(forward.forward.call).toBeDefined();
        expect(forward.forward.call.position).toBeDefined();
        expect(forward.forward.call.resolves_to.length).toBe(1);
        expect(forward.forward.call.port).toBe("prophecy");
        expect(forward.forward.kinds.length).toBe(1);
        expect(forward.forward.leaves).toBeDefined();
        expect(forward.forward.leaves.length).toBeGreaterThanOrEqual(1);
        expect(forward.forward.local_trace).toBeDefined();

        const backward = issue.traces.find((t: any) => t.backward);
        expect(backward).toBeDefined();
        expect(backward.backward.call).toBeDefined();
        expect(backward.backward.call.position).toBeDefined();
        expect(backward.backward.call.resolves_to.length).toBe(1);
        expect(backward.backward.call.port).toBe("prophecy");
        expect(backward.backward.kinds.length).toBe(1);
        expect(backward.backward.leaves).toBeDefined();
        expect(backward.backward.leaves.length).toBeGreaterThanOrEqual(1);
        expect(backward.backward.local_trace).toBeDefined();
    });

    it("uri-handler-rce: features include expected prophecy-* entries", async () => {
        const result = await analyzeSappFixture("uri-handler-rce");
        const issue = JSON.parse(readSappIssuesNdjson(result).trim().split("\n")[0]);
        const features: string[] = issue.features;

        expect(features.some((f: string) => f.startsWith("prophecy-handle:"))).toBe(true);
        expect(features.some((f: string) => f.startsWith("prophecy-source-kind:"))).toBe(true);
        expect(features.some((f: string) => f.startsWith("prophecy-sink-kind:"))).toBe(true);
        expect(features.some((f: string) => f.startsWith("prophecy-severity:"))).toBe(true);
        expect(features.some((f: string) => f.startsWith("prophecy-category:"))).toBe(true);
    });

    it("uri-handler-rce: sappMetadata is present with correct tool name and rules", async () => {
        const result = await analyzeSappFixture("uri-handler-rce");
        expect(result.sappMetadata).toBeDefined();
        expect(result.sappMetadata!.sapper.tool).toBe("prophecy");
        expect(result.sappMetadata!.sapper.filename_glob).toBe("*.sapp");
        expect(result.sappMetadata!.runner.version).toBe("unknown");
        expect(result.sappMetadata!.runner.project).toBe("uri-handler-rce");
        expect(Array.isArray(result.sappMetadata!.sapper.rules)).toBe(true);
        expect(result.sappMetadata!.sapper.rules.length).toBeGreaterThanOrEqual(9);
        const rceRule = result.sappMetadata!.sapper.rules.find((r: any) => r.code === 9001);
        expect(rceRule).toBeDefined();
        expect(rceRule!.name).toBe("Prophecy-RCE");
        expect(result.sappMetadata!.sapper.rules).toContainEqual({
            code: 9099,
            name: "Prophecy-Unknown",
            description: "Modeled tainted data flow with an unknown category; exploitability not established",
        });
    });

    it("package-json-entry: sappMetadata project defaults to package name", async () => {
        const result = await analyzeSappFixture("package-json-entry");
        expect(result.sappMetadata!.runner.project).toBe("test-extension");
    });

    it("uri-handler-rce: sappMetadata project can be overridden", async () => {
        const result = await analyze({
            projectDir: path.join(FIXTURES, "uri-handler-rce"),
            spec: vscodeExtensionSpec,
            maxDepth: 5,
            outputFormat: "sapp-json",
            sappProject: "vscode",
        });
        expect(result.sappMetadata!.runner.project).toBe("vscode");
    });

    it("sanitized-input: SAPP output is empty file for no findings", async () => {
        const result = await analyzeSappFixture("sanitized-input");
        expect(readSappIssuesNdjson(result)).toBe("");
        expect(readSappTraceFramesNdjson(result)).toBe("");
    });

    it("multi-file-rce: propagation_steps are present for multi-step flows", async () => {
        const result = await analyzeSappFixture("multi-file-rce");
        const lines = readSappIssuesNdjson(result).trim().split("\n");
        expect(lines.length).toBe(1);

        const issue = JSON.parse(lines[0]);
        expect(issue.propagation_steps).toBeDefined();
        expect(Array.isArray(issue.propagation_steps)).toBe(true);
        expect(issue.propagation_steps.length).toBeGreaterThan(0);
        for (const step of issue.propagation_steps) {
            expect(step.kind).toBeDefined();
            expect(step.location).toBeDefined();
            expect(step.location.line).toBeGreaterThan(0);
            expect(step.description).toBeDefined();
        }

        const traceFrames = readSappTraceFramesNdjson(result)
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
        const forward = issue.traces.find((trace: any) => trace.forward).forward;
        expect(traceFrames.filter((frame: any) => frame.type === "postcondition").length).toBe(
            forward.kinds[0].trace_len,
        );
        expect(traceFrames.filter((frame: any) => frame.type === "precondition").length).toBe(1);
        expect(traceFrames.every((frame: any) => frame.caller_port === "prophecy")).toBe(true);
        // Steps on one line share a frame, but every step keeps its own feature.
        const stepFeatures = traceFrames.flatMap((frame: any) =>
            frame.features.filter((feature: any) => String(feature.name).startsWith("prophecy-step-")),
        );
        expect(stepFeatures.length).toBe(issue.propagation_steps.length);
    });

    it("executecommand-bridge-rce: produces one NDJSON issue for the reachable flow", async () => {
        const result = await analyzeSappFixture("executecommand-bridge-rce");
        const lines = readSappIssuesNdjson(result).trim().split("\n");
        expect(lines.length).toBe(1);

        for (const line of lines) {
            const issue = JSON.parse(line);
            expect(issue.kind).toBe("issue");
            expect(issue.code).toBe(9001);
            expect(issue.traces.length).toBe(2);
        }
    });

    it("uri-handler-rce: handle is deterministic across runs", async () => {
        const result1 = await analyzeSappFixture("uri-handler-rce");
        const result2 = await analyzeSappFixture("uri-handler-rce");
        const handle1 = JSON.parse(readSappIssuesNdjson(result1).trim().split("\n")[0]).handle;
        const handle2 = JSON.parse(readSappIssuesNdjson(result2).trim().split("\n")[0]).handle;
        expect(handle1).toBe(handle2);
    });

    describe("handle stability", () => {
        async function sappIssuesForSource(source: string): Promise<any[]> {
            const result = await analyze({
                source,
                fileName: "/src/extension.ts",
                spec: vscodeExtensionSpec,
                maxDepth: 5,
                outputFormat: "sapp-json",
            });
            return readSappIssuesNdjson(result)
                .trim()
                .split("\n")
                .filter(Boolean)
                .map((line) => JSON.parse(line));
        }

        const handler = `
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        exec(uri.query);
                        exec(uri.path);
                    }
                });`;

        it("handles survive line and column shifts from unrelated edits", async () => {
            const before = await sappIssuesForSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";
                export function activate() {${handler}
                }
            `);
            const after = await sappIssuesForSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";

                // Unrelated code added above the sink.
                function unrelated(): number {
                    return 1;
                }

                export function activate() {
                    const count = unrelated();
                    console.log(count);
                    ${handler}
                }
            `);

            expect(before.length).toBe(2);
            expect(after.map((i) => i.position.line)).not.toEqual(before.map((i) => i.position.line));
            expect(after.map((i) => i.handle).sort()).toEqual(before.map((i) => i.handle).sort());
        });

        it("identical sinks in one scope get distinct handles", async () => {
            const issues = await sappIssuesForSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";
                export function activate() {${handler}
                }
            `);
            expect(new Set(issues.map((i) => i.handle)).size).toBe(2);
            expect(issues.map((i) => i.callable)).toEqual([
                "/src/extension.ts::activate>handleUri",
                "/src/extension.ts::activate>handleUri",
            ]);
        });

        it("one sink reached from several entry points shares a handle", async () => {
            const issues = await sappIssuesForSource(`
                import * as vscode from "vscode";
                import { exec } from "child_process";
                function runConfigured() {
                    exec(vscode.workspace.getConfiguration("ext").get<string>("cmd")!);
                }
                export function activate(context: vscode.ExtensionContext) {
                    runConfigured();
                    context.subscriptions.push(
                        vscode.commands.registerCommand("ext.run", () => runConfigured()),
                    );
                }
            `);
            const entryPoints = new Set(
                issues.map((i) => i.features.find((f: string) => f.startsWith("prophecy-entrypoint:"))),
            );
            expect(entryPoints.size).toBeGreaterThan(1);
            expect(new Set(issues.map((i) => i.handle)).size).toBe(1);
            expect(issues[0].callable).toBe("/src/extension.ts::runConfigured");
        });
    });

    it("long SAPP handles keep their hash suffix after truncation", () => {
        const result = {
            findings: [
                {
                    handle: `source|exec|${"entry".repeat(80)}|long.ts|123`,
                    sinkSite: `${"scope>".repeat(40)}call:exec#0`,
                    source: {
                        kind: "parameter",
                        pattern: "source",
                        description: "source",
                    },
                    sourceLocation: {
                        fileName: "long.ts",
                        line: 1,
                        column: 1,
                        text: "source",
                    },
                    sink: {
                        kind: "callArgument",
                        name: "exec",
                        pattern: "child_process.exec",
                        argPositions: [0],
                        description: "exec",
                        severity: "critical",
                        categories: ["rce"],
                    },
                    sinkLocation: {
                        fileName: `${"/very-long-directory".repeat(20)}/extension.ts`,
                        line: 123,
                        column: 4,
                        text: "exec(cmd)",
                    },
                    propagationChain: [],
                },
            ],
        } as AnalyzerResult;

        const issue = JSON.parse(readSappIssuesNdjson(result));
        expect(issue.handle).toHaveLength(255);
        expect(issue.handle).toMatch(/:[0-9a-f]{16}$/);
    });

    it("workspace-config-rce: warning code maps correctly for rce category", async () => {
        const result = await analyzeSappFixture("workspace-config-rce");
        const issue = JSON.parse(readSappIssuesNdjson(result).trim().split("\n")[0]);
        expect(issue.code).toBe(9001);
        expect(issue.features).toContain("prophecy-category:rce");
    });
});

describe("E2E: Lint output format with fix suggestions", () => {
    function analyzeLintFixture(name: string) {
        return analyzeFixture(name, {
            outputFormat: "lint",
        });
    }

    // Deeplink URI → exec(prompt) — should suggest execFile
    it("uri-handler-rce: produces valid lint JSON Lines with execFile suggestion", async () => {
        const result = await analyzeLintFixture("uri-handler-rce");
        const lines = result.formattedOutput.trim().split("\n");
        expect(lines.length).toBeGreaterThanOrEqual(1);

        for (const line of lines) {
            const msg = JSON.parse(line);
            expect(msg.path).toBeDefined();
            expect(msg.line).toBeGreaterThan(0);
            expect(msg.code).toMatch(/^PROPHECY-/);
        }

        const finding = JSON.parse(lines[0]);
        expect(finding.code).toBe("PROPHECY-RCE");
        expect(finding.severity).toBe("error");
        expect(finding.replacement).toBeDefined();
        expect(finding.replacement).toContain("execFile");
        expect(finding.replacementIsSafe).toBe(false);

        // Fixes must remain available through the API as well as formatted
        // lint output.
        const fixableFindings = result.findings.filter((f) => f.fix);
        expect(fixableFindings.length).toBeGreaterThanOrEqual(1);
        expect(fixableFindings[0].fix!.replacement).toContain("execFile");
        expect(fixableFindings[0].fix!.applicability).toBe("unsafe");
    });

    // Based on D53663037: deeplink → exec(`git clone ${repo}`) template literal
    it("template-literal-injection: suggests execFile with split args for template literal", async () => {
        const result = await analyzeLintFixture("template-literal-injection");
        const lines = result.formattedOutput.trim().split("\n");
        expect(lines.length).toBeGreaterThanOrEqual(1);

        const finding = JSON.parse(lines[0]);
        expect(finding.code).toBe("PROPHECY-RCE");
        expect(finding.replacement).toBeDefined();
        expect(finding.replacement).toContain("execFile");
        expect(finding.replacement).toContain('"git"');
    });

    // Based on D91753663: deeplink → terminal.sendText(cmd) — should suggest quote()
    it("class-uri-handler-terminal: suggests quote() wrapping for sendText", async () => {
        const result = await analyzeLintFixture("class-uri-handler-terminal");
        const lines = result.formattedOutput.trim().split("\n");
        expect(lines.length).toBeGreaterThanOrEqual(1);

        const sendTextMsg = lines
            .map((l: string) => JSON.parse(l))
            .find((m: any) => m.code === "PROPHECY-RCE" && m.replacement?.includes("quote"));

        expect(sendTextMsg).toBeDefined();
        expect(sendTextMsg.replacement).toContain("quote(");
    });

    // Based on D95600124: executeCommand findings have no auto-fix
    it("websocket-server-rce: executeCommand findings have no fix (unfixable)", async () => {
        const result = await analyzeLintFixture("websocket-server-rce");
        const lines = result.formattedOutput.trim().split("\n");
        expect(lines.length).toBeGreaterThanOrEqual(1);

        const execCmdMsgs = lines
            .map((l: string) => JSON.parse(l))
            .filter((m: any) => m.code === "PROPHECY-RCE" && m.name.includes("executeCommand"));

        expect(execCmdMsgs.length).toBeGreaterThanOrEqual(1);
        for (const msg of execCmdMsgs) {
            expect(msg.original).toBeUndefined();
            expect(msg.replacement).toBeUndefined();
        }
    });

    it("sanitized-input: lint output is empty", async () => {
        const result = await analyzeLintFixture("sanitized-input");
        expect(result.formattedOutput).toBe("");
    });
});

describe("E2E: Custom spec — Express server", () => {
    function analyzeExpressFixture(name: string) {
        return analyzeFixture(name, {
            spec: expressSpec,
        });
    }

    it("express-rce: detects req.query → exec (command injection)", async () => {
        const result = await analyzeExpressFixture("express-rce");
        expect(result.findings.some((f) => f.sink.pattern.includes("exec"))).toBe(true);
    });

    it("express-rce: detects req.query → res.send (reflected XSS)", async () => {
        const result = await analyzeExpressFixture("express-rce");
        expect(result.findings.some((f) => f.sink.name === "send")).toBe(true);
    });

    it("express-rce: detects req.query → res.redirect (open redirect)", async () => {
        const result = await analyzeExpressFixture("express-rce");
        expect(result.findings.some((f) => f.sink.pattern.includes("redirect"))).toBe(true);
    });

    it("express-rce: detects req.params → res.sendFile (path traversal)", async () => {
        const result = await analyzeExpressFixture("express-rce");
        expect(result.findings.some((f) => f.sink.pattern.includes("sendFile"))).toBe(true);
    });

    it("express-rce: detects POST req.body → exec", async () => {
        const result = await analyzeExpressFixture("express-rce");
        const postExecFindings = result.findings.filter(
            (f) => f.sink.name === "exec" && f.source.callbackRegistration === "express.Application.post",
        );
        expect(postExecFindings.length).toBe(1);
    });

    it("express-rce: detects POST req.body → spawn options", async () => {
        const result = await analyzeExpressFixture("express-rce");
        const spawnFindings = result.findings.filter(
            (f) => f.sink.pattern.includes("spawn") && f.source.callbackRegistration === "express.Application.post",
        );
        expect(spawnFindings.length).toBe(1);
    });

    it("express-rce: detects POST req.body.path → writeFile destination", async () => {
        const result = await analyzeExpressFixture("express-rce");
        expect(result.findings.some((f) => f.sink.name === "writeFile_path")).toBe(true);
    });

    it("express-rce: detects app.all() route handler", async () => {
        const result = await analyzeExpressFixture("express-rce");
        const allFindings = result.findings.filter((f) => f.source.callbackRegistration === "express.Application.all");
        expect(allFindings.length).toBe(1);
    });

    it("express-rce: router.get detects reflected XSS", async () => {
        const result = await analyzeExpressFixture("express-rce");
        const routerFindings = result.findings.filter(
            (f) => f.sink.name === "send" && f.sinkLocation.fileName.includes("router"),
        );
        expect(routerFindings.length).toBe(1);
    });

    it("express-rce: parseInt sanitizer blocks exec finding on /safe/kill route", async () => {
        const result = await analyzeExpressFixture("express-rce");
        // /run (GET), /execute (POST), and /admin (all) produce exec findings.
        // /safe/kill does NOT — parseInt("7; rm -rf /") → 7, stripping the payload.
        const execFindings = result.findings.filter((f) => f.sink.name === "exec");
        expect(execFindings.length).toBe(3);
    });

    it("express-rce: includes all shared Node.js sink families", async () => {
        const result = await analyzeExpressFixture("express-rce");
        const sinkNames = new Set(result.findings.map((f) => f.sink.name));

        expect([...sinkNames].sort()).toEqual(
            expect.arrayContaining([
                "Function",
                "execFile_options",
                "execFileSync",
                "execFileSync_args",
                "execFileSync_options",
                "https_request",
                "spawnSync",
                "spawnSync_args",
                "spawnSync_options",
            ]),
        );
    });
});
