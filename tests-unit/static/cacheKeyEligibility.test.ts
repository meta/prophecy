/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseSource } from "../../src/static/parser";
import { TaintSpec } from "../../src/static/spec/types";
import { InterproceduralAnalyzer } from "../../src/static/taint/interprocedural";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "Input", taintAllProperties: true }],
    sinks: [
        {
            kind: "callArgument",
            name: "sink",
            pattern: "sink",
            argPositions: [0],
            categories: ["rce"],
            severity: "critical",
            description: "Sink",
        },
    ],
    sanitizers: [],
};

async function scan(body: string) {
    const source = `import * as vscode from "vscode";
        declare function input(): string;
        declare function sink(value: unknown): void;
        ${body}`;
    const fileName = path.join(__dirname, "cache-key-eligibility.ts");
    const parsed = parseSource(source, fileName);
    expect(parsed.program.getSemanticDiagnostics()).toEqual([]);
    const proto = InterproceduralAnalyzer.prototype as unknown as {
        getCallCacheKey(...args: unknown[]): string;
        functionArgumentsCacheKey(...args: unknown[]): string;
        cachedCallResult(...args: unknown[]): unknown;
    };
    const keys = jest.spyOn(proto, "getCallCacheKey");
    const fragments = jest.spyOn(proto, "functionArgumentsCacheKey");
    const probes = jest.spyOn(proto, "cachedCallResult");
    try {
        const result = await analyze({ source, fileName, spec, outputFormat: "json" });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.metrics.performance.callCacheKeyBuilds).toBe(keys.mock.calls.length);
        return {
            result,
            operations: {
                keys: keys.mock.calls.length,
                fragments: fragments.mock.calls.length,
                probes: probes.mock.calls.length,
            },
        };
    } finally {
        keys.mockRestore();
        fragments.mockRestore();
        probes.mockRestore();
    }
}

function expectNoCache(checked: Awaited<ReturnType<typeof scan>>) {
    expect(checked.operations).toEqual({ keys: 0, fragments: 0, probes: 0 });
    expect(checked.result.cacheHits).toBe(0);
    expect(checked.result.metrics.performance.callResultCacheStores).toBe(0);
}

function expectCommandBridge(checked: Awaited<ReturnType<typeof scan>>) {
    for (const finding of checked.result.findings) {
        expect(finding.propagationChain.some((step) => step.description.includes("passed via executeCommand"))).toBe(
            true,
        );
    }
}

describe("call-cache eligibility before key construction", () => {
    it("does no cache work for receiver calls and still evaluates defaults", async () => {
        const checked = await scan(`
            class Box {
                constructor(public value: string) {}
                observe(extra: string = "safe") {
                    sink(this.value);
                    sink(extra);
                }
            }
            export function main() {
                const box = new Box(input());
                box.observe(); box.observe(); box.observe();
                const clean = new Box("safe"); clean.observe();
            }
        `);
        expect(checked.result.findings.map((finding) => finding.sinkLocation.text)).toEqual(["sink(this.value)"]);
        expectNoCache(checked);
    });

    it.each(["ordinary", "command", "runtime command"])(
        "does no cache work for %s calls with object arguments",
        async (route) => {
            const invoke = route !== "ordinary" ? 'vscode.commands.executeCommand("test.observe",' : "observe(";
            const register = 'vscode.commands.registerCommand("test.observe", observe);';
            const checked = await scan(`
            function observe(box: { value: string }, extra: string = "safe") {
                sink(box.value);
                sink(extra);
            }
            ${route === "command" ? register : ""}
            export function main() {
                ${route === "runtime command" ? register : ""}
                const box = { value: input() };
                ${invoke} box); ${invoke} box); ${invoke} box);
                ${invoke} { value: "safe" });
            }
        `);
            expect(checked.result.findings.map((finding) => finding.sinkLocation.text)).toEqual(["sink(box.value)"]);
            if (route !== "ordinary") expectCommandBridge(checked);
            expectNoCache(checked);
        },
    );

    it("skips keys for function values with captured instances", async () => {
        const checked = await scan(`
            function apply(fn: () => string) { return fn(); }
            export function main() {
                const box = { value: input() };
                const read = () => box.value;
                sink(apply(read));
                sink(apply(read));
            }
        `);
        expect(checked.result.findings).toHaveLength(2);
        expectNoCache(checked);
    });

    it.each(["ordinary", "command", "runtime command"])(
        "retains %s pure reuse and distinct default-argument keys",
        async (route) => {
            const invoke = route !== "ordinary" ? 'vscode.commands.executeCommand("test.identity",' : "identity(";
            const omit = route !== "ordinary" ? 'vscode.commands.executeCommand("test.identity")' : "identity()";
            const register = 'vscode.commands.registerCommand("test.identity", identity);';
            const checked = await scan(`
            function identity(value: string = "safe") { return value; }
            ${route === "command" ? register : ""}
            export function main() {
                ${route === "runtime command" ? register : ""}
                const value = input();
                sink(${invoke} value));
                sink(${invoke} value));
                sink(${omit});
            }
        `);
            expect(checked.result.findings).toHaveLength(2);
            if (route !== "ordinary") expectCommandBridge(checked);
            expect(checked.operations).toEqual({ keys: 3, fragments: 3, probes: 3 });
            expect(checked.result.cacheHits).toBe(1);
            expect(checked.result.metrics.performance.callResultCacheStores).toBe(2);
        },
    );
});
