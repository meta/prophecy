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
        fileName: "/src/this-parameter.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

// A `this` parameter types the receiver and takes no argument position.
describe("functions that declare a this parameter", () => {
    it("binds a method's arguments after its this parameter", async () => {
        expect(
            await check(`
            class Runner { run(this: Runner, input: string) { exec(input); } }
            register(input => new Runner().run(input));
        `),
        ).toHaveLength(1);
    });

    it("binds each argument to its own parameter", async () => {
        const findings = await check(`
            class Runner {
                first(this: Runner, value: string, other: string) { exec(value); }
                second(this: Runner, value: string, other: string) { exec(other); }
            }
            register(input => {
                new Runner().first("fixed", input);
                new Runner().second("fixed", input);
            });
        `);
        expect(findings.map((finding) => finding.sinkLocation.line)).toEqual([4]);
    });

    it("binds a function's arguments after its this parameter", async () => {
        expect(
            await check(`
            function run(this: void, input: string) { exec(input); }
            register(input => run(input));
        `),
        ).toHaveLength(1);
    });

    it("taints a callback's first value parameter", async () => {
        expect(
            await check(`
            register(function (this: void, input: string) { exec(input); });
        `),
        ).toHaveLength(1);
    });
});
