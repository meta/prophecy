/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "Untrusted input", taintAllProperties: true }],
    sinks: [
        {
            kind: "callArgument",
            name: "sink",
            pattern: "sink",
            categories: ["rce"],
            severity: "critical",
            description: "Executable input",
        },
    ],
    sanitizers: [],
};

async function scan(source: string) {
    const result = await analyze({
        source: `declare function input(): string;
            declare function sink(value: unknown): void;
            ${source}`,
        fileName: "/src/call-evaluation.ts",
        spec,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result;
}

describe("call evaluation order", () => {
    it.each([false, true])("evaluates receiver writes before argument reads: clean=%s", async (clean) => {
        const result = await scan(`
            function receiver(box: { value: string }) {
                box.value = ${clean ? '"fixed"' : "input()"};
                return { consume(value: string) { sink(value); } };
            }
            export function main() {
                const box = { value: "" };
                ${clean ? "box.value = input();" : ""}
                receiver(box).consume(box.value);
            }
        `);
        expect(result.findings).toHaveLength(clean ? 0 : 1);
    });

    it("evaluates a computed callee key before its arguments", async () => {
        const result = await scan(`
            function key(box: { value: string }) { box.value = input(); return "consume" as const; }
            export function main() {
                const box = { value: "" };
                const target = { consume(_value: void) {} };
                target[key(box)](sink(box.value));
            }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toBe("sink(box.value)");
    });

    it.each([false, true])("keeps the receiver selected before an argument rebind: clean=%s", async (clean) => {
        const result = await scan(`
            class Box {
                constructor(public value: string) {}
                consume(_other: Box) { sink(this.value); }
            }
            export function main() {
                const original = new Box(${clean ? '"fixed"' : "input()"});
                const replacement = new Box(${clean ? "input()" : '"fixed"'});
                let selected = original;
                selected.consume(selected = replacement);
            }
        `);
        expect(result.findings).toHaveLength(clean ? 0 : 1);
    });

    it.each([false, true])("keeps the function selected before an argument rebind: clean=%s", async (clean) => {
        const result = await scan(`
            export function main() {
                const dirty = (_other: unknown, value: string) => { sink(value); };
                const clean = (_other: unknown, _value: string) => {};
                let selected = ${clean ? "clean" : "dirty"};
                selected(selected = ${clean ? "dirty" : "clean"}, input());
            }
        `);
        expect(result.findings).toHaveLength(clean ? 0 : 1);
    });

    it("reads a declared function's captured bindings after argument evaluation", async () => {
        const result = await scan(`
            export function main() {
                let command = input();
                function consume(_value: string) { sink(command); }
                consume(command = "fixed");
            }
        `);
        expect(result.findings).toHaveLength(0);
    });

    it.each([4, 12])("visits a chain of %i unresolved methods linearly", async (length) => {
        const result = await scan(`export function main() { sink(input()${".trim()".repeat(length)}); }`);
        expect(result.findings).toHaveLength(1);
        expect(result.metrics.performance.callExpressions).toBe(length + 2);
    });

    it("does not reuse receiver values across later evaluations of the same body", async () => {
        const result = await scan(`
            function consume(box: { value: string }) { sink(box.value.trim()); }
            export function main() {
                const box = { value: "" };
                consume(box);
                box.value = input();
                consume(box);
            }
        `);
        expect(result.findings).toHaveLength(1);
    });

    it("does not evaluate arguments again when the sort model declines", async () => {
        const result = await scan(`
            declare function comparator(): (left: string, right: string) => number;
            export function main() { const values = ["a", "b"]; values.sort(comparator()); }
        `);
        expect(result.metrics.performance.callExpressions).toBe(2);
    });

    it("evaluates a forEach receiver once while analyzing its synchronous callback", async () => {
        const result = await scan(`
            function values() { return [input()]; }
            export function main() { values().forEach(value => sink(value)); }
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.metrics.performance.callExpressions).toBe(4);
    });

    it("keeps an unreachable Promise callback unexecuted", async () => {
        const result = await scan(`
            export function main() { Promise.reject("fixed").then(() => sink(input())); }
        `);
        expect(result.findings).toHaveLength(0);
    });
});
