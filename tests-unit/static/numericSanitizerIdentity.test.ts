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
import { SanitizerSpec, SinkCategory, TaintSpec } from "../../src/static/spec/types";

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

async function check(
    body: string,
    declarations = "",
    category: SinkCategory = "code_injection",
    sanitizers: SanitizerSpec[] = spec.sanitizers,
) {
    const source = `declare function input(): string; declare function observe(value: unknown): void;
        ${declarations}
        export function main() { ${body} }`;
    const fileName = path.join(__dirname, "numeric-sanitizer-input.ts");
    expect(
        parseSource(source, fileName)
            .program.getSemanticDiagnostics()
            .map((diagnostic) => diagnostic.code),
    ).toEqual([]);
    const result = await analyze({
        source,
        fileName,
        spec: { ...spec, sinks: [{ ...spec.sinks[0], categories: [category] }], sanitizers },
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("numeric sanitizer binding identity", () => {
    it.each(["Number", "parseInt", "globalThis.Number", "globalThis.parseInt", "Number.parseInt"])(
        "keeps genuine %s conversion scoped to injection syntax",
        async (callee) => {
            expect(await check(`observe(${callee}(input()));`)).toHaveLength(0);
            expect(await check(`observe(${callee}(input()));`, "", "ssrf")).toHaveLength(1);
        },
    );

    it.each(["Number", "parseInt"])("preserves const aliases of the global %s", async (callee) => {
        expect(await check("observe(convert(input()));", `const convert = ${callee};`)).toHaveLength(0);
    });

    it.each(["Number", "parseInt"])("does not sanitize a local %s identity function", async (callee) => {
        expect(
            await check(`observe(${callee}(input()));`, `function ${callee}(value: string) { return value; }`),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("does not sanitize an object method named %s", async (callee) => {
        expect(
            await check(
                `observe(local.${callee}(input()));`,
                `const local = { ${callee}(value: string) { return value; } };`,
            ),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("does not sanitize an imported %s lookalike", async (callee) => {
        expect(
            await check(
                `observe(${callee}(input()));`,
                `import { ${callee} } from "./fixtures/numeric-sanitizer-identity/lookalikes";`,
            ),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("analyzes side effects inside a local %s", async (callee) => {
        expect(
            await check(`${callee}(input());`, `function ${callee}(value: string) { observe(value); return 0; }`),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("checks global identity for named and inline %s map callbacks", async (callee) => {
        for (const callback of [callee, `(value) => ${callee}(value)`]) {
            const body = `observe([input()].map(${callback}).join(""));`;
            expect(await check(body)).toHaveLength(0);
            expect(await check(body, `function ${callee}(value: string) { return value; }`)).toHaveLength(1);
        }
    });

    it.each(["Number", "parseInt"])("rejects reassigned same-name aliases of %s", async (callee) => {
        expect(
            await check(`
            let ${callee}: any = globalThis.${callee};
            ${callee} = (value: string) => value;
            observe(${callee}(input()));
        `),
        ).toHaveLength(1);
    });

    it("rejects direct reassignment of global Number", async () => {
        expect(
            await check(`
            Number = ((value: string) => value) as any;
            observe(Number(input()));
        `),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("rejects globalThis replacement of %s", async (callee) => {
        expect(
            await check(`
            globalThis.${callee} = ((value: string) => value) as any;
            observe(globalThis.${callee}(input()));
        `),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("checks reassigned %s aliases in map callbacks", async (callee) => {
        expect(
            await check(`
            let ${callee}: any = globalThis.${callee};
            ${callee} = (value: string) => value;
            observe([input()].map(${callee}).join(""));
        `),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("reconciles a globalThis %s write with a bare read", async (callee) => {
        expect(
            await check(`
            globalThis.${callee} = ((value: string) => value) as any;
            observe(${callee}(input()));
        `),
        ).toHaveLength(1);
    });

    it("reconciles a bare Number write with a globalThis read", async () => {
        expect(
            await check(`
            Number = ((value: string) => value) as any;
            observe(globalThis.Number(input()));
        `),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("preserves %s aliases captured before global replacement", async (callee) => {
        for (const captured of [callee, `globalThis.${callee}`]) {
            expect(
                await check(`
                const convert = ${captured};
                globalThis.${callee} = ((value: string) => value) as any;
                observe(convert(input()));
            `),
            ).toHaveLength(0);
        }
    });

    it.each(["Number", "parseInt"])("rejects %s aliases captured after global replacement", async (callee) => {
        expect(
            await check(`
            globalThis.${callee} = ((value: string) => value) as any;
            const convert = ${callee};
            observe(convert(input()));
        `),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("checks global-object aliases and bracket writes for %s", async (callee) => {
        expect(
            await check(`
            const globals = globalThis;
            globals["${callee}"] = ((value: string) => value) as any;
            observe(${callee}(input()));
        `),
        ).toHaveLength(1);
    });

    it.each(["Number", "parseInt"])("snapshots %s identity before argument effects", async (callee) => {
        expect(
            await check(`
            observe((${callee} as any)(input(), globalThis.${callee} = ((value: string) => value) as any));
        `),
        ).toHaveLength(0);
    });

    it("snapshots Number before an argument assigns the bare global", async () => {
        expect(
            await check(`
            observe((Number as any)(input(), Number = ((value: string) => value) as any));
        `),
        ).toHaveLength(0);
    });

    it.each(["Number", "parseInt"])(
        "does not restore %s identity when a later argument restores the binding",
        async (callee) => {
            expect(
                await check(`
            const original = ${callee};
            globalThis.${callee} = ((value: string) => value) as any;
            observe((globalThis.${callee} as any)(input(), globalThis.${callee} = original));
        `),
            ).toHaveLength(1);
        },
    );

    it.each(["Number", "parseInt"])(
        "checks cross-spelling writes before map callback capture for %s",
        async (callee) => {
            expect(
                await check(`
            globalThis.${callee} = ((value: string) => value) as any;
            observe([input()].map(${callee}).join(""));
        `),
            ).toHaveLength(1);
        },
    );

    it("does not treat a typed local receiver as the global Number object", async () => {
        expect(
            await check(`
            const local = { parseInt: (value: string) => value } as unknown as NumberConstructor;
            observe(local.parseInt(input()));
        `),
        ).toHaveLength(1);
    });

    it("keeps Number.parseInt independent of the global parseInt binding", async () => {
        expect(
            await check(`
            globalThis.parseInt = ((value: string) => value) as any;
            observe(Number.parseInt(input()));
        `),
        ).toHaveLength(0);
    });

    it.each(["window", "self"])("recognizes the same library binding through %s", async (receiver) => {
        expect(await check(`observe(${receiver}.Number(input()));`)).toHaveLength(0);
        expect(
            await check(`
            globalThis.Number = ((value: string) => value) as any;
            observe(${receiver}.Number(input()));
        `),
        ).toHaveLength(1);
        expect(
            await check(`
            ${receiver}.Number = ((value: string) => value) as any;
            observe(Number(input()));
        `),
        ).toHaveLength(1);
    });

    it("retains explicitly configured custom sanitizers without builtin identity", async () => {
        const custom: SanitizerSpec = {
            kind: "callReturnValue",
            pattern: "normalize",
            description: "Caller-defined normalization contract",
            categories: ["code_injection"],
        };
        expect(
            await check(
                "observe(normalize(input()));",
                "declare function normalize(value: string): string;",
                "code_injection",
                [custom],
            ),
        ).toHaveLength(0);
        expect(
            await check("observe(normalize(input()));", "declare function normalize(value: string): string;", "ssrf", [
                custom,
            ]),
        ).toHaveLength(1);
    });
});
