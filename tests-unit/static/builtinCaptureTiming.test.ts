/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseSource } from "../../src/static/parser";
import { NumberSanitizer, ParseIntSanitizer } from "../../src/static/spec/sanitizers";
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
    sanitizers: [NumberSanitizer, ParseIntSanitizer],
};

async function check(body: string, declarations = "") {
    const source = `declare function input(): string; declare function observe(value: unknown): void;
        ${declarations}
        export function main() { ${body} }`;
    const fileName = path.join(__dirname, "builtin-capture-input.ts");
    expect(
        parseSource(source, fileName)
            .program.getSemanticDiagnostics()
            .map((diagnostic) => diagnostic.code),
    ).toEqual([]);
    const result = await analyze({ source, fileName, spec, outputFormat: "json" });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe.each(["Number", "parseInt"])("%s capture and helper invocation timing", (callee) => {
    const assignment = `${callee === "Number" ? callee : `globalThis.${callee}`} = ((value: string) => value) as any;`;
    const helper = `function mutate() { ${assignment} return input(); }`;

    it("preserves a module-initialization capture before an entry function writes", async () => {
        expect(await check(`${assignment} observe(convert(input()));`, `const convert = ${callee};`)).toHaveLength(0);
    });

    it("rejects a module capture after a top-level helper call", async () => {
        expect(
            await check("observe(convert(input()));", `${helper} mutate(); const convert = ${callee};`),
        ).toHaveLength(1);
    });

    it("preserves a module capture before a later top-level helper call", async () => {
        expect(
            await check("observe(convert(input()));", `${helper} const convert = ${callee}; mutate();`),
        ).toHaveLength(0);
    });

    it("selects the native callee before an argument helper runs", async () => {
        expect(await check(`${helper} observe(${callee}(mutate()));`)).toHaveLength(0);
    });

    it("rejects a read after a helper has already run", async () => {
        expect(await check(`${helper} mutate(); observe(${callee}(input()));`)).toHaveLength(1);
    });

    it("rejects a const capture after a helper has already run", async () => {
        expect(await check(`${helper} mutate(); const convert = ${callee}; observe(convert(input()));`)).toHaveLength(
            1,
        );
    });

    it("preserves a const capture before a later helper call", async () => {
        expect(await check(`${helper} const convert = ${callee}; mutate(); observe(convert(input()));`)).toHaveLength(
            0,
        );
    });

    it("follows const helper aliases without treating their creation as invocation", async () => {
        expect(await check(`${helper} const invoke = mutate; observe(${callee}(invoke()));`)).toHaveLength(0);
    });

    it("does not trust an earlier unknown callback invocation", async () => {
        expect(
            await check(
                `${helper} invoke(mutate); observe(${callee}(input()));`,
                "declare function invoke(callback: () => string): void;",
            ),
        ).toHaveLength(1);
    });

    it("does not trust a capture after a helper escaped to unknown code", async () => {
        expect(
            await check(
                `${helper} invoke(mutate); const convert = ${callee}; observe(convert(input()));`,
                "declare function invoke(callback: () => string): void;",
            ),
        ).toHaveLength(1);
    });

    it("tracks a private top-level helper called only in the argument", async () => {
        expect(await check(`observe(${callee}(mutate()));`, helper)).toHaveLength(0);
    });

    it("does not assume an independently exported helper has not run", async () => {
        expect(await check(`observe(${callee}(input()));`, `export ${helper}`)).toHaveLength(1);
    });

    it.each([
        ["function", `export ${helper}`],
        ["const callback", `export const mutate = () => { ${assignment} return input(); };`],
    ])("keeps exported namespace %s invocation timing unresolved", async (_name, declaration) => {
        expect(await check(`observe(${callee}(input()));`, `export namespace Helpers { ${declaration} }`)).toHaveLength(
            1,
        );
    });

    it("projects nested helper calls to their invocation in the reading scope", async () => {
        expect(
            await check(`${helper} function invoke() { return mutate(); } observe(${callee}(invoke()));`),
        ).toHaveLength(0);
    });

    it("retains uncertainty when a later loop call can affect the next iteration", async () => {
        expect(
            await check(`${helper} for (let i = 0; i < 2; i++) { observe(${callee}(input())); mutate(); }`),
        ).toHaveLength(1);
    });

    it("keeps possible reentrant module-initialization calls conservative", async () => {
        expect(
            await check(
                "observe(convert(input()));",
                `declare function initialize(): void; export ${helper} initialize(); const convert = ${callee};`,
            ),
        ).toHaveLength(1);
    });

    it("evaluates a helper's numeric argument before its body writes", async () => {
        expect(
            await check(
                `function mutate(value: number) { ${assignment} return value; } observe(mutate(${callee}(input())));`,
            ),
        ).toHaveLength(0);
    });
});
