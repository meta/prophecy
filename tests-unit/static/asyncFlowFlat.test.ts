/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { analyze } from "../../src/static/analyzer";
import { vscodeSpecWithEnvSource } from "./testUtils";

async function scan(body: string, declarations = "") {
    const result = await analyze({
        source: `import {exec, execFile} from 'child_process';
            import {readdir} from 'fs/promises';
            import * as vscode from 'vscode';
            ${declarations}
            export async function activate() { ${body} }`,
        fileName: "/src/asyncFlowFlat.ts",
        spec: vscodeSpecWithEnvSource,
        maxDepth: 5,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("asyncFlow native Array.flat", () => {
    it("retains record fields through async map, Promise.all and flat", async () => {
        const findings = await scan(`
            async function names() {
                try {
                    const entries = await readdir('/workspace', {withFileTypes: true});
                    return entries.filter(entry => entry.isDirectory()).map(entry => entry.name);
                } catch { return []; }
            }
            async function records() {
                const entries = await names();
                const groups = await Promise.all(entries.map(async command => [{command, label: 'fixed'}]));
                return groups.flat();
            }
            const rows = await records();
            execFile('git', ['diff', rows[0].command]);
            exec(rows[0].label);
        `);
        expect(findings).toHaveLength(1);
        expect(findings[0].source.pattern).toBe("fs.readdir");
        expect(findings[0].sink.name).toBe("execFile_args");
    });

    it.each(["", "1", "undefined"])("flattens one level for depth %s", async (depth) => {
        const findings = await scan(`
            const rows = [[{command: process.env.INPUT, label: 'fixed'}]].flat(${depth});
            exec(rows[0].command);
            exec(rows[0].label);
        `);
        expect(findings).toHaveLength(1);
        expect(findings[0].sinkLocation.text).toBe("exec(rows[0].command)");
    });

    it("retains known scalar order and skips holes and empty arrays", async () => {
        const findings = await scan(`
            const values = [, ['fixed', , process.env.INPUT], []].flat();
            exec(values[0]);
            exec(values[1]);
        `);
        expect(findings).toHaveLength(1);
        expect(findings[0].sinkLocation.text).toBe("exec(values[1])");
    });

    it("does not flatten a nested layer at depth zero", async () => {
        const findings = await scan(`
            const values = [[{command: process.env.INPUT}]].flat(0);
            exec(values[0][0].command);
        `);
        expect(findings).toHaveLength(1);
    });

    it("makes a fresh outer container at depth zero", async () => {
        expect(
            await scan(`
            const input = [['fixed']];
            const output = input.flat(0);
            output[0] = [process.env.INPUT];
            exec(input[0][0]);
        `),
        ).toEqual([]);
    });

    it("preserves inner array aliases at depth zero", async () => {
        const findings = await scan(`
            const inner = ['fixed'];
            const output = [inner].flat(0);
            output[0][0] = process.env.INPUT;
            exec(inner[0]);
        `);
        expect(findings).toHaveLength(1);
    });

    it("does not alias flattened output slots with the input inner array", async () => {
        expect(
            await scan(`
            const inner = ['fixed'];
            const output = [inner].flat();
            output[0] = process.env.INPUT;
            exec(inner[0]);
        `),
        ).toEqual([]);
    });

    it("copies scalar slots rather than observing later input slot replacements", async () => {
        expect(
            await scan(`
            const inner = ['fixed'];
            const output = [inner].flat();
            inner[0] = process.env.INPUT;
            exec(output[0]);
        `),
        ).toEqual([]);
    });

    it.each([
        "record.command = process.env.INPUT; exec(output[0].command);",
        "output[0].command = process.env.INPUT; exec(record.command);",
    ])("preserves leaf object identity: %s", async (mutation) => {
        const findings = await scan(`
            const record = {command: 'fixed'};
            const output = [[record]].flat();
            ${mutation}
        `);
        expect(findings).toHaveLength(1);
    });

    it("does not replace the original leaf when an output slot is replaced", async () => {
        expect(
            await scan(`
            const record = {command: 'fixed'};
            const output = [[record]].flat();
            output[0] = {command: process.env.INPUT};
            exec(record.command);
        `),
        ).toEqual([]);
    });

    it("keeps non-array objects as elements", async () => {
        const findings = await scan(`
            const record = {command: process.env.INPUT, label: 'fixed'};
            const output = [record].flat();
            exec(output[0].command);
            exec(output[0].label);
        `);
        expect(findings).toHaveLength(1);
    });

    it("retains unknown source cardinality despite an empty alternative", async () => {
        const findings = await scan(`
            const input = vscode.workspace.getConfiguration('demo').get<Array<Array<{command: string}>>>('groups') || [];
            const output = input.flat();
            exec(output[0].command);
        `);
        expect(findings).toHaveLength(1);
    });

    it("visits callbacks for a source-free array with unknown cardinality", async () => {
        const findings = await scan(
            `
            const output = unknownGroups().flat().map(() => process.env.INPUT);
            exec(output.join(''));
        `,
            "declare function unknownGroups(): string[][];",
        );
        expect(findings).toHaveLength(1);
    });

    it("does not let an empty alternative erase unknown source-free cardinality", async () => {
        const findings = await scan(
            `
            const groups = unknownGroups() || [];
            const output = groups.flat().map(() => process.env.INPUT);
            exec(output.join(''));
        `,
            "declare function unknownGroups(): string[][] | undefined;",
        );
        expect(findings).toHaveLength(1);
    });

    it("retains a scalar alternative beside a known empty array result", async () => {
        const findings = await scan(
            `
            function choice() { return flag ? [].flat() : 'fixed'; }
            const output = [choice()].flat().map(() => process.env.INPUT);
            exec(output.join(''));
        `,
            "declare const flag: boolean;",
        );
        expect(findings).toHaveLength(1);
    });

    it("does not invent elements in a definitely empty array", async () => {
        expect(
            await scan(`
            const input: string[][] = [];
            const output = input.flat().map(() => process.env.INPUT);
            exec(output.join(''));
        `),
        ).toEqual([]);
    });

    it.each(["2", "Infinity", "depth"])("preserves taint conservatively for depth %s", async (depth) => {
        const findings = await scan(
            `
            const output = [[[{command: process.env.INPUT, label: 'fixed'}]]].flat(${depth});
            exec(output[0].command);
            exec(output[0].label);
        `,
            "declare const depth: number;",
        );
        expect(findings).toHaveLength(1);
        expect(findings[0].sinkLocation.text).toBe("exec(output[0].command)");
    });

    it("bounds cycles for an unknown depth without dropping known data", async () => {
        const findings = await scan(
            `
            const input: any[] = [];
            input[0] = input;
            input[1] = {command: process.env.INPUT};
            const output = input.flat(depth);
            exec(output[0].command);
        `,
            "declare const depth: number;",
        );
        expect(findings).toHaveLength(1);
    });

    it("does not treat a depth argument as element data", async () => {
        expect(
            await scan(`
            const output = [['fixed']].flat(Number(process.env.INPUT));
            exec(output[0]);
        `),
        ).toEqual([]);
    });

    it("respects an own flat override", async () => {
        expect(
            await scan(`
            const input = [[process.env.INPUT]];
            input.flat = () => ['fixed'];
            exec(input.flat()[0]);
        `),
        ).toEqual([]);
    });

    it("does not model unrelated methods named flat", async () => {
        expect(
            await scan(`
            const object = {data: process.env.INPUT, flat() { return ['fixed']; }};
            exec(object.flat()[0]);
        `),
        ).toEqual([]);
    });
});
