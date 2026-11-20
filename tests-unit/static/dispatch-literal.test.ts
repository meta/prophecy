/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { ExecSink } from "../../src/static/spec/sinks";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    sources: [
        {
            kind: "parameter",
            pattern: "register.input",
            description: "External input",
            callbackRegistration: "register",
            paramIndex: 0,
            taintAllProperties: true,
        },
    ],
    sinks: [ExecSink],
    sanitizers: [],
};

async function check(source: string) {
    const result = await analyze({
        source: `import { exec } from "child_process"; declare function register(callback: (input: string) => void): void; ${source}`,
        fileName: "/src/dispatch-literal.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

// The receiver is a parameter, so no concrete instance selects the target.
const invoke = `function invoke(runner: Runner, input: string) { runner.run(input); }
    declare const runner: Runner;
    register(input => invoke(runner, input));`;

describe("dispatch to object-literal implementations", () => {
    it("dispatches an interface call to an annotated literal", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            const literal: Runner = { run(input: string) { exec(input); } };
            ${invoke}
        `),
        ).toHaveLength(1);
    });

    it("dispatches to a literal returned from a factory with a declared return type", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            const make = (): Runner => ({ run(input: string) { exec(input); } });
            ${invoke}
        `),
        ).toHaveLength(1);
    });

    it("dispatches to function-valued properties, shorthand members, and a this parameter", async () => {
        const findings = await check(`
            interface Runner { run(this: Runner, input: string): void }
            function named(this: Runner, input: string) { exec(input); }
            const run = function (this: Runner, input: string) { exec(input); };
            const arrow: Runner = { run: (input: string) => { exec(input); } };
            const reference: Runner = { run: named };
            const shorthand: Runner = { run };
            ${invoke}
        `);
        expect(findings.map((finding) => finding.sinkLocation.line).sort()).toEqual([3, 4, 5]);
    });

    it("dispatches through a type alias, an intersection, an assertion, and a typed argument", async () => {
        const findings = await check(`
            type Runner = { run(input: string): void };
            type Named = Runner & { name: string };
            const intersection: Named = { name: "a", run(input: string) { exec(input); } };
            const asserted = { run(input: string) { exec(input); } } as Runner;
            declare function install(runner: Runner): void;
            install({ run(input: string) { exec(input); } });
            ${invoke}
        `);
        expect(findings.map((finding) => finding.sinkLocation.line).sort()).toEqual([4, 5, 7]);
    });

    it("dispatches a base-interface call to a literal typed as a sub-interface", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            interface Special extends Runner { run(input: string): void; extra: boolean }
            const literal: Special = { extra: true, run(input: string) { exec(input); } };
            ${invoke}
        `),
        ).toHaveLength(1);
    });

    it("reports a method inherited through a spread once", async () => {
        expect(
            await check(`
            interface Runner { name: string; run(input: string): void }
            const base: Runner = { name: "base", run(input: string) { exec(input); } };
            const derived: Runner = { ...base, name: "derived" };
            ${invoke}
        `),
        ).toHaveLength(1);
    });

    it("joins literal and class implementations", async () => {
        const findings = await check(`
            interface Runner { run(input: string): void }
            class Unsafe implements Runner { run(input: string) { exec(input); } }
            const literal: Runner = { run(input: string) { exec(input); } };
            ${invoke}
        `);
        expect(findings.map((finding) => finding.sinkLocation.line).sort()).toEqual([3, 4]);
    });

    it("does not dispatch to a safe literal or to another interface's literal", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            interface Other { run(input: string): void }
            const safe: Runner = { run(input: string) { exec("fixed"); } };
            const other: Other = { run(input: string) { exec(input); } };
            ${invoke}
        `),
        ).toHaveLength(0);
    });

    it("runs a const literal's own member rather than another implementation", async () => {
        const findings = await check(`
            interface Runner { run(input: string): void }
            const unsafe: Runner = { run(input: string) { exec(input); } };
            const safe: Runner = { run(input: string) { exec("fixed"); } };
            const other: Runner = { run(input: string) { exec(input); } };
            register(input => { safe.run(input); other.run(input); });
        `);
        expect(findings.map((finding) => finding.sinkLocation.line)).toEqual([5]);
    });

    // Unchanged: a member another literal declares keeps its own body as the only target.
    it("does not index a literal typed after another literal", async () => {
        expect(
            await check(`
            const safe = { run(input: string) { exec("fixed"); } };
            const unsafe: typeof safe = { run(input: string) { exec(input); } };
            function invoke(runner: typeof safe, input: string) { runner.run(input); }
            declare const runner: typeof safe;
            register(input => invoke(runner, input));
        `),
        ).toHaveLength(0);
    });

    // Known limit: an unannotated literal has no contextual type to index.
    it("does not dispatch to a literal that reaches the interface only by shape", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            const literal = { run(input: string) { exec(input); } };
            const typed: Runner = literal;
            ${invoke}
        `),
        ).toHaveLength(0);
    });

    it.each([
        [8, 8],
        [9, 0],
    ])("analyzes %i literal implementations and reports %i", async (count, expected) => {
        const literals = Array.from(
            { length: count },
            (_, index) => `const literal${index}: Runner = { run(input: string) { exec(input); } };`,
        ).join("\n");
        expect(
            await check(`
            interface Runner { run(input: string): void }
            ${literals}
            ${invoke}
        `),
        ).toHaveLength(expected);
    });
});
