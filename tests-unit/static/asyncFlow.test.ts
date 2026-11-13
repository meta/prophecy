/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { analyzeFixture, vscodeSpecWithEnvSource } from "./testUtils";

async function analyzeFlow(body: string, helpers = "") {
    return analyze({
        source: `import { exec } from "child_process";
            ${helpers}
            export async function activate() { ${body} }`,
        fileName: "/src/asyncFlow.ts",
        spec: vscodeSpecWithEnvSource,
        outputFormat: "text",
        maxDepth: 8,
    });
}

describe("asyncFlow host models", () => {
    it("preserves callback results and instances across files", async () => {
        const result = await analyzeFixture("asyncFlow", { spec: vscodeSpecWithEnvSource, maxDepth: 10 });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(4);
        expect(result.findings.every((finding) => finding.sinkLocation.fileName.endsWith("stages.ts"))).toBe(true);
        expect(
            result.findings.every(
                (finding) => new Set(finding.propagationChain.map((step) => step.location.fileName)).size >= 2,
            ),
        ).toBe(true);
    });

    it.each([
        ["fulfillment parameter", "Promise.resolve(process.env.INPUT).then(value => exec(value));"],
        ["then callback result", "Promise.resolve('fixed').then(() => process.env.INPUT).then(value => exec(value));"],
        ["all fulfillment", "Promise.all([Promise.resolve(process.env.INPUT)]).then(([value]) => exec(value));"],
        ["map callback result", "exec(['fixed'].map(() => process.env.INPUT).join(' '));"],
        ["map parameter", "[process.env.INPUT].map(value => exec(value));"],
        ["filter element", "exec([process.env.INPUT].filter(() => true).join(' '));"],
        [
            "factory callback",
            "const callback = make(process.env.INPUT); Promise.resolve('fixed').then(callback).then(value => exec(value));",
        ],
        [
            "named factory callback",
            "const callback = makeNamed(process.env.INPUT); Promise.resolve('fixed').then(callback).then(value => exec(value));",
        ],
        ["rejection handler", "Promise.reject(process.env.INPUT).then(undefined, value => exec(value));"],
        ["awaited fulfillment", "exec(await Promise.resolve(process.env.INPUT));"],
        ["async function fulfillment", "asyncValue(process.env.INPUT).then(value => exec(value));"],
        [
            "then adopted promise",
            "Promise.resolve('fixed').then(() => Promise.resolve(process.env.INPUT)).then(value => exec(value));",
        ],
        ["all rejection channel", "Promise.all([Promise.reject(process.env.INPUT)]).catch(value => exec(value));"],
        ["recovered rejection", "Promise.reject(process.env.INPUT).catch(value => value).then(value => exec(value));"],
        ["map receiver identity", "[new Command(process.env.INPUT)].map(value => value)[0].run();"],
        ["filter receiver identity", "[new Command(process.env.INPUT)].filter(() => true)[0].run();"],
        [
            "branch promise payload",
            "const value = process.env.CHOICE ? Promise.resolve(process.env.INPUT) : Promise.resolve('fixed'); value.then(value => exec(value));",
        ],
    ])("propagates %s", async (_name, body) => {
        const result = await analyzeFlow(
            body,
            `
            function make(value: string) { return () => value; }
            async function asyncValue(value: string) { return value; }
            function makeNamed(value: string) { function callback() { return value; } return callback; }
            class Command { constructor(private command: string) {} run() { exec(this.command); } }
        `,
        );
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([
        ["then clean return", "Promise.resolve(process.env.INPUT).then(() => 'fixed').then(value => exec(value));"],
        ["map clean return", "exec([process.env.INPUT].map(() => 'fixed').join(' '));"],
        ["filter predicate result", "exec(['fixed'].filter(() => process.env.INPUT).join(' '));"],
        ["fulfillment is not rejection", "Promise.resolve(process.env.INPUT).then(undefined, value => exec(value));"],
        ["rejection is not fulfillment", "Promise.reject(process.env.INPUT).then(value => exec(value));"],
        ["unrelated map", "exec(({ map: (_cb: any) => ['fixed'] }).map(() => process.env.INPUT).join(' '));"],
        [
            "unrelated then",
            "const object = { then: (_cb: any) => 'fixed' }; exec(object.then(() => process.env.INPUT));",
        ],
        [
            "separate promises",
            "const tainted = Promise.resolve(process.env.INPUT); const clean = Promise.resolve('fixed'); clean.then(value => exec(value));",
        ],
        [
            "all preserves clean index",
            "Promise.all([Promise.resolve('fixed'), Promise.resolve(process.env.INPUT)]).then(values => exec(values[0]));",
        ],
        [
            "all rejects without fulfillment",
            "Promise.all([Promise.reject(process.env.INPUT)]).then(values => exec(values[0]));",
        ],
        ["empty map has no callback", "[].map(() => process.env.INPUT).forEach(value => exec(value));"],
        ["fulfillment does not run catch", "Promise.resolve('fixed').catch(() => exec(process.env.INPUT));"],
        [
            "shadowed Promise",
            "const Promise = { resolve: (_value: string) => ({ then: (_callback: any) => 'fixed' }) }; exec(Promise.resolve(process.env.INPUT).then((value: string) => value));",
        ],
        [
            "map override",
            "const values = [process.env.INPUT]; values.map = () => ['fixed']; exec(values.map(value => value)[0]);",
        ],
        ["promise handle is not its fulfillment", "exec(Promise.resolve(process.env.INPUT));"],
    ])("keeps %s clean", async (_name, body) => {
        const result = await analyzeFlow(body);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });
});
