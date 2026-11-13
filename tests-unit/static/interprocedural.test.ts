/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { InterproceduralAnalyzer, EntryPoint } from "../../src/static/taint/interprocedural";
import { parseSource } from "../../src/static/parser";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { initTaintValueHashing } from "../../src/static/taint/taintValue";

describe("InterproceduralAnalyzer entry-point isolation", () => {
    beforeAll(async () => {
        await initTaintValueHashing();
    });

    it("skips a throwing entry point with a warning and still analyzes the rest", () => {
        // Two independent findings-producing entry points: a URI handler and
        // a command handler, each flowing tainted input into child_process.exec.
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate(context: vscode.ExtensionContext) {
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        exec(uri.query);
                    }
                });
                vscode.commands.registerCommand("ext.cmd", (arg: string) => {
                    exec(arg);
                });
            }
        `,
            "/src/extension.ts",
        );

        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entryPoints = analyzer.discoverEntryPoints(sourceFiles);
        expect(entryPoints.length).toBeGreaterThanOrEqual(2);

        // Simulate one entry point exhausting V8's native call stack (the
        // codetrust deep-string-concat failure mode). The analyzer must
        // isolate it — record a warning and keep going — not abort the run.
        const original = analyzer.analyzeEntryPoint.bind(analyzer);
        let threwOnce = false;
        jest.spyOn(analyzer, "analyzeEntryPoint").mockImplementation((ep: EntryPoint) => {
            if (!threwOnce) {
                threwOnce = true;
                throw new RangeError("Maximum call stack size exceeded");
            }
            return original(ep);
        });

        let result!: ReturnType<typeof analyzer.analyzeEntryPoints>;
        expect(() => {
            result = analyzer.analyzeEntryPoints(entryPoints);
        }).not.toThrow();

        // A stack overflow is a tolerable structured skip; surviving entry
        // points must still be analyzed.
        const overflowSkip = result.skippedEntryPoints.find((s) =>
            s.reason.includes("Maximum call stack size exceeded"),
        );
        expect(overflowSkip).toBeDefined();
        expect(overflowSkip!.unexpected).toBe(false);
        expect(result.findings.length).toBeGreaterThanOrEqual(1);
    });

    it("flags a non-limit error as unexpected but still continues the scan", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate(context: vscode.ExtensionContext) {
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        exec(uri.query);
                    }
                });
                vscode.commands.registerCommand("ext.cmd", (arg: string) => {
                    exec(arg);
                });
            }
        `,
            "/src/extension.ts",
        );

        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entryPoints = analyzer.discoverEntryPoints(sourceFiles);
        expect(entryPoints.length).toBeGreaterThanOrEqual(2);

        // An error that is neither a stack overflow nor a time-budget timeout
        // (e.g. a latent analyzer bug) must be flagged `unexpected` — but must
        // NOT abort the run in the default (non-strict) mode.
        const original = analyzer.analyzeEntryPoint.bind(analyzer);
        let threwOnce = false;
        jest.spyOn(analyzer, "analyzeEntryPoint").mockImplementation((ep: EntryPoint) => {
            if (!threwOnce) {
                threwOnce = true;
                throw new TypeError("cannot read properties of undefined (reading 'foo')");
            }
            return original(ep);
        });

        let result!: ReturnType<typeof analyzer.analyzeEntryPoints>;
        expect(() => {
            result = analyzer.analyzeEntryPoints(entryPoints);
        }).not.toThrow();

        const unexpected = result.skippedEntryPoints.filter((s) => s.unexpected);
        expect(unexpected).toHaveLength(1);
        expect(unexpected[0].reason).toContain("cannot read properties of undefined");
        // Surviving entry points are still analyzed.
        expect(result.findings.length).toBeGreaterThanOrEqual(1);
    });

    it("treats a non-stack-overflow RangeError as unexpected", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate(context: vscode.ExtensionContext) {
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        exec(uri.query);
                    }
                });
                vscode.commands.registerCommand("ext.cmd", (arg: string) => {
                    exec(arg);
                });
            }
        `,
            "/src/extension.ts",
        );

        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entryPoints = analyzer.discoverEntryPoints(sourceFiles);
        expect(entryPoints.length).toBeGreaterThanOrEqual(2);

        // A RangeError that is NOT a stack overflow (e.g. "Invalid array
        // length") is a real bug, not a tolerable limit — it must be flagged
        // unexpected, not lumped in with stack-overflow limit skips.
        const original = analyzer.analyzeEntryPoint.bind(analyzer);
        let threwOnce = false;
        jest.spyOn(analyzer, "analyzeEntryPoint").mockImplementation((ep: EntryPoint) => {
            if (!threwOnce) {
                threwOnce = true;
                throw new RangeError("Invalid array length");
            }
            return original(ep);
        });

        const result = analyzer.analyzeEntryPoints(entryPoints);
        const skip = result.skippedEntryPoints.find((s) => s.reason.includes("Invalid array length"));
        expect(skip).toBeDefined();
        expect(skip!.unexpected).toBe(true);
    });

    it("re-raises unexpected errors when PROPHECY_STRICT=1", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate(context: vscode.ExtensionContext) {
                vscode.commands.registerCommand("ext.cmd", (arg: string) => {
                    exec(arg);
                });
            }
        `,
            "/src/extension.ts",
        );

        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entryPoints = analyzer.discoverEntryPoints(sourceFiles);
        jest.spyOn(analyzer, "analyzeEntryPoint").mockImplementation(() => {
            throw new TypeError("boom");
        });

        const prev = process.env.PROPHECY_STRICT;
        process.env.PROPHECY_STRICT = "1";
        try {
            expect(() => analyzer.analyzeEntryPoints(entryPoints)).toThrow("boom");
        } finally {
            if (prev === undefined) {
                delete process.env.PROPHECY_STRICT;
            } else {
                process.env.PROPHECY_STRICT = prev;
            }
        }
    });

    it("skips an entry point that exceeds its time budget", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate(context: vscode.ExtensionContext) {
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        exec(uri.query);
                    }
                });
            }
        `,
            "/src/extension.ts",
        );

        // 5ms budget; drive the wall clock past the deadline deterministically.
        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5, undefined, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entryPoints = analyzer.discoverEntryPoints(sourceFiles);
        expect(entryPoints.length).toBeGreaterThanOrEqual(1);

        // First Date.now() (in analyzeEntryPoint) sets the deadline; every
        // later call (the cooperative checks in analyzeFunctionCall) reports a
        // time well past it, so the entry point is abandoned and skipped.
        const nowSpy = jest.spyOn(Date, "now");
        nowSpy.mockReturnValueOnce(1_000); // deadline = 1005
        nowSpy.mockReturnValue(1_000_000); // every subsequent check is past it

        const result = analyzer.analyzeEntryPoints(entryPoints);
        nowSpy.mockRestore();

        const budgetSkip = result.skippedEntryPoints.find((s) => s.reason.includes("exceeded time budget"));
        expect(budgetSkip).toBeDefined();
        // The budget timeout is a tolerable limit (classified via the typed
        // EntryPointTimeBudgetExceededError), not an analyzer bug.
        expect(budgetSkip!.unexpected).toBe(false);
    });

    it("produces no warnings when every entry point analyzes cleanly", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate(context: vscode.ExtensionContext) {
                vscode.commands.registerCommand("ext.cmd", (arg: string) => {
                    exec(arg);
                });
            }
        `,
            "/src/extension.ts",
        );

        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entryPoints = analyzer.discoverEntryPoints(sourceFiles);

        const result = analyzer.analyzeEntryPoints(entryPoints);
        expect(result.skippedEntryPoints).toHaveLength(0);
    });

    it("retains caller and nested findings at a deadline and continues with the next entry", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            declare function expire(): void;
            export function activate() {
                vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                    exec("caller " + uri.query);
                    function nested(command: string) {
                        exec("nested " + command);
                        expire();
                        exec("unvisited nested " + command);
                    }
                    nested(uri.query);
                    exec("unvisited caller " + uri.query);
                }});
                vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                    exec("next " + uri.query);
                }});
            }
        `,
            "/src/deadline.ts",
        );
        const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5, undefined, 5);
        analyzer.buildVSCodeCommandRegistry(sourceFiles);
        const entries = analyzer.discoverEntryPoints(sourceFiles).filter((entry) => entry.kind === "uriHandler");
        expect(entries).toHaveLength(2);
        let now = 1_000;
        const clock = jest.spyOn(Date, "now").mockImplementation(() => now);
        const original = analyzer.analyzeFunctionCall;
        const call = jest.spyOn(analyzer, "analyzeFunctionCall").mockImplementation(function (...args) {
            // Expire inside a real nested analysis, after its first sink is visited.
            if (args[0].expression.getText() === "expire") now += 100;
            return original.apply(analyzer, args);
        });
        try {
            const result = analyzer.analyzeEntryPoints(entries);
            expect(result.skippedEntryPoints).toHaveLength(1);
            expect(result.skippedEntryPoints[0].reason).toContain("exceeded time budget (5ms)");
            expect(result.skippedEntryPoints[0].unexpected).toBe(false);
            expect(result.findings.map((finding) => finding.sinkLocation.text).sort()).toEqual([
                'exec("caller " + uri.query)',
                'exec("nested " + command)',
                'exec("next " + uri.query)',
            ]);
        } finally {
            call.mockRestore();
            clock.mockRestore();
        }
    });
});
