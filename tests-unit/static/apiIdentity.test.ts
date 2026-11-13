/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { parseSource } from "../../src/static/parser";
import { APIIdentityCache } from "../../src/static/taint/apiIdentity";
import { createAnalysisMetrics } from "../../src/static/metrics";
import { InterproceduralAnalyzer } from "../../src/static/taint/interprocedural";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { initTaintValueHashing } from "../../src/static/taint/taintValue";

function parseCalls(source: string) {
    const parsed = parseSource(source, "identity.ts");
    const calls: ts.Expression[] = [];
    const visit = (node: ts.Node) => {
        if (ts.isCallExpression(node)) calls.push(node.expression);
        node.forEachChild(visit);
    };
    visit(parsed.program.getSourceFile("identity.ts")!);
    return { ...parsed, calls };
}

describe("API identity memoization", () => {
    beforeAll(initTaintValueHashing);

    it("retains aliases, computed paths and globals while rejecting local and cyclic roots", () => {
        const { checker, calls } = parseCalls(`
            import { exec as run } from "child_process";
            import * as fs from "fs";
            const alias = run;
            const first = second;
            const second = first;
            declare const key: string;
            run(); alias(); fs["readFileSync"](); fs[key](); first(); process.cwd();
            function local(process: { cwd(): void }) { process.cwd(); }
        `);
        const cache = APIIdentityCache.forChecker(checker);
        const expected = [
            "child_process.exec",
            "child_process.exec",
            "fs.readFileSync",
            undefined,
            undefined,
            "process.cwd",
            undefined,
        ];
        expect(calls.map((call) => cache.importedName(call))).toEqual(expected);
        expect(calls.map((call) => cache.hasExternalRoot(call))).toEqual([true, true, true, false, false, true, false]);
        const symbolLookup = jest.spyOn(checker, "getSymbolAtLocation");
        try {
            const reused = APIIdentityCache.forChecker(checker);
            expect(reused).toBe(cache);
            expect(calls.map((call) => reused.importedName(call))).toEqual(expected);
            expect(calls.map((call) => reused.hasExternalRoot(call))).toEqual([
                true,
                true,
                true,
                false,
                false,
                true,
                false,
            ]);
            expect(symbolLookup).not.toHaveBeenCalled();
        } finally {
            symbolLookup.mockRestore();
        }
    });

    it("isolates declaration facts between programs even when they reuse an AST", () => {
        const source = ts.createSourceFile("shared.ts", "api.run();", ts.ScriptTarget.ES2020, true);
        const build = (external: boolean) => {
            const host = ts.createCompilerHost({ noLib: true });
            host.getSourceFile = (name) =>
                name === "shared.ts"
                    ? source
                    : ts.createSourceFile(name, "declare const api: { run(): void };", ts.ScriptTarget.ES2020, true);
            const program = ts.createProgram(["shared.ts", external ? "api.d.ts" : "api.ts"], { noLib: true }, host);
            return program.getTypeChecker();
        };
        const call = (source.statements[0] as ts.ExpressionStatement).expression as ts.CallExpression;
        const external = APIIdentityCache.forChecker(build(true));
        expect(external.isExternalSymbol(call.expression)).toBe(true);
        expect(external.hasExternalRoot(call.expression)).toBe(true);
        const local = APIIdentityCache.forChecker(build(false));
        expect(local.isExternalSymbol(call.expression)).toBe(false);
        expect(local.hasExternalRoot(call.expression)).toBe(false);
    });

    it("preserves findings, match counters and debug records when another analyzer reuses the checker", () => {
        const { checker, sourceFiles } = parseSource(
            `
            import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate() {
                vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                    function fixed(input: string) { return "echo safe"; }
                    exec(fixed(uri.query));
                    exec(uri.query);
                }});
            }
        `,
            "identity.ts",
        );
        const run = () => {
            const metrics = createAnalysisMetrics({ enableDebug: true });
            const analyzer = new InterproceduralAnalyzer(checker, vscodeExtensionSpec, 5, metrics);
            const entries = analyzer.discoverEntryPoints(sourceFiles).filter((entry) => entry.kind === "uriHandler");
            return { result: analyzer.analyzeEntryPoints(entries), metrics };
        };
        const first = run();
        const reused = run();
        expect(first.result.findings).toHaveLength(1);
        expect(reused.result).toEqual(first.result);
        expect(reused.metrics.patternMatching).toEqual(first.metrics.patternMatching);
        expect(first.metrics.patternMatching.typeResolutionAttempts).toBeGreaterThan(0);
        expect(first.metrics.performance.typeResolutionCacheMisses).toBeGreaterThan(0);
        expect(reused.metrics.performance.typeResolutionCacheMisses).toBe(0);
    });
});
