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

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "External input" }],
    sinks: [
        {
            kind: "callArgument",
            name: "observe",
            pattern: "observe",
            description: "Observed input",
            categories: ["code_injection"],
        },
    ],
    sanitizers: [],
};

async function check(source: string) {
    source = `declare function input(): string; declare function observe(value: unknown): void; ${source}`;
    const fileName = path.join(__dirname, "dispatch-overflow-input.ts");
    expect(
        parseSource(source, fileName)
            .program.getSemanticDiagnostics()
            .map((diagnostic) => diagnostic.code),
    ).toEqual([]);
    const result = await analyze({
        source,
        fileName,
        spec,
        maxDepth: 8,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

function children(count: number, body = "return value;") {
    return Array.from(
        { length: count },
        (_, index) => `class Child${index} extends Base { convert(value: string): string { ${body} } }`,
    ).join("\n");
}

describe("open dispatch candidate overflow", () => {
    it.each([7, 8, 9])("retains return passthrough with a base body and %i overrides", async (count) => {
        expect(
            await check(`
            class Base { convert(value: string): string { return "fixed"; } }
            ${children(count)}
            export function main(receiver: Base) { observe(receiver.convert(input())); }
        `),
        ).toHaveLength(1);
    });

    it.each([7, 8, 9])("retains base-body findings as well as uncertain returns with %i overrides", async (count) => {
        expect(
            await check(`
            class Base { convert(value: string): string { observe(value); return "fixed"; } }
            ${children(count)}
            export function main(receiver: Base) { observe(receiver.convert(input())); }
        `),
        ).toHaveLength(2);
    });

    it("keeps a base-only clean return precise", async () => {
        expect(
            await check(`
            class Base { convert(value: string): string { return "fixed"; } }
            export function main(receiver: Base) { observe(receiver.convert(input())); }
        `),
        ).toHaveLength(0);
    });

    it("keeps exhaustive concrete receivers precise above the open-hierarchy cap", async () => {
        const findings = await check(`
            class Base { convert(value: string): string { return "fixed"; } }
            ${children(9)}
            function invoke(receiver: Base, value: string) { return receiver.convert(value); }
            export function main() {
                observe(invoke(new Base(), input()));
                observe(invoke(new Child8(), input()));
            }
        `);
        expect(findings).toHaveLength(1);
        expect(findings[0].sinkLocation.text).toContain("new Child8()");
    });

    it("retains passthrough for a bodyless interface above the cap", async () => {
        expect(
            await check(`
            interface Runner { convert(value: string): string }
            ${Array.from({ length: 9 }, (_, i) => `class Child${i} implements Runner { convert(value: string) { return value; } }`).join("\n")}
            export function main(receiver: Runner) { observe(receiver.convert(input())); }
        `),
        ).toHaveLength(1);
    });

    it("does not infer that every overflowing alternative throws", async () => {
        expect(
            await check(`
            class Base { convert(value: string): string { throw new Error("stop"); } }
            ${children(9)}
            export function main(receiver: Base) {
                receiver.convert("fixed");
                observe(input());
            }
        `),
        ).toHaveLength(1);
    });

    it.each([7, 8, 9])("retains an argument object's dirty value across %i possible clears", async (count) => {
        expect(
            await check(`
            class Base { clear(box: { value: string }) { box.value = "fixed"; } }
            ${Array.from({ length: count }, (_, i) => `class Child${i} extends Base { clear(box: { value: string }) {} }`).join("\n")}
            export function main(receiver: Base) {
                const box = { value: "fixed" };
                box.value = input();
                receiver.clear(box);
                observe(box.value);
            }
        `),
        ).toHaveLength(1);
    });

    it.each([7, 8, 9])("preserves an external alias across %i possible clears", async (count) => {
        expect(
            await check(`
            class Base { clear(box: { value: string }) { box.value = "fixed"; } }
            ${Array.from({ length: count }, (_, i) => `class Child${i} extends Base { clear(box: { value: string }) {} }`).join("\n")}
            export function main(receiver: Base) {
                const box = { value: "fixed" };
                box.value = input();
                const alias = box;
                receiver.clear(box);
                observe(alias.value);
            }
        `),
        ).toHaveLength(1);
    });

    it("retains base-body findings and the unchanged heap alternative together", async () => {
        expect(
            await check(`
            class Base { clear(box: { value: string }) { observe(box.value); box.value = "fixed"; } }
            ${Array.from({ length: 9 }, (_, i) => `class Child${i} extends Base { clear(box: { value: string }) {} }`).join("\n")}
            export function main(receiver: Base) {
                const box = { value: "fixed" };
                box.value = input();
                receiver.clear(box);
                observe(box.value);
            }
        `),
        ).toHaveLength(2);
    });

    it("does not discard a known base write when joining the unknown alternative", async () => {
        expect(
            await check(`
            class Base { store(box: { value: string }, value: string) { box.value = value; } }
            ${Array.from({ length: 9 }, (_, i) => `class Child${i} extends Base { store(box: { value: string }, value: string) {} }`).join("\n")}
            export function main(receiver: Base) {
                const box = { value: "fixed" };
                receiver.store(box, input());
                observe(box.value);
            }
        `),
        ).toHaveLength(1);
    });

    it("keeps concrete base clears strong despite an overflowing open hierarchy", async () => {
        expect(
            await check(`
            class Base { clear(box: { value: string }) { box.value = "fixed"; } }
            ${Array.from({ length: 9 }, (_, i) => `class Child${i} extends Base { clear(box: { value: string }) {} }`).join("\n")}
            export function main() {
                const box = { value: "fixed" };
                box.value = input();
                new Base().clear(box);
                observe(box.value);
            }
        `),
        ).toHaveLength(0);
    });

    it.each([7, 8, 9])("preserves returned argument aliases across %i possible clears", async (count) => {
        expect(
            await check(`
            class Base { clear(box: { value: string }) { box.value = "fixed"; return box; } }
            ${Array.from({ length: count }, (_, i) => `class Child${i} extends Base { clear(box: { value: string }) { return box; } }`).join("\n")}
            export function main(receiver: Base) {
                const box = { value: "fixed" };
                box.value = input();
                const alias = receiver.clear(box);
                observe(alias.value);
            }
        `),
        ).toHaveLength(1);
    });

    it("does not leak open-return uncertainty into a concrete safe call", async () => {
        const findings = await check(`
            class Base { convert(value: string): string { return "fixed"; } }
            ${children(9)}
            function invoke(receiver: Base, value: string) { return receiver.convert(value); }
            export function main(receiver: Base) {
                observe(invoke(receiver, input()));
                observe(invoke(new Base(), input()));
                observe(invoke(receiver, input()));
            }
        `);
        expect(findings).toHaveLength(2);
        expect(findings.every((finding) => !finding.sinkLocation.text?.includes("new Base()"))).toBe(true);
    });
});
