/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { analyze } from "../../src/static/analyzer";
import { vscodeSpecWithEnvSource } from "./testUtils";

async function scan(body: string, maxDepth = 8) {
    return analyze({
        source: `import { exec } from "child_process";
            import { promisify } from "util";
            import * as fs from "fs";
            import * as vscode from "vscode";
            const execAsync = promisify(exec);
            declare const flag: boolean;
            export async function activate() { ${body} }`,
        fileName: "/src/asyncFlowMixedReturns.ts",
        spec: vscodeSpecWithEnvSource,
        maxDepth,
        outputFormat: "text",
    });
}

describe("asyncFlow mixed scalar and Promise returns", () => {
    it("retains an explicit configured command while examining asynchronous fallback paths", async () => {
        const result = await scan(`
            function configuredPath(): string | undefined {
                return vscode.workspace.getConfiguration('demo').get<string>('binaryPath');
            }
            async function exists(file: string) {
                try { await fs.promises.stat(file); return true; } catch { return false; }
            }
            async function locate(binary: string): Promise<string> {
                try {
                    const output = await execAsync('which ' + binary);
                    return Promise.resolve(output.stdout.trim());
                } catch { return Promise.reject(new Error('not installed')); }
            }
            async function binaryPath(): Promise<string> {
                const configured = configuredPath();
                if (configured !== undefined && configured !== '') return configured;
                if (await exists('/usr/local/bin/demo')) return '/usr/local/bin/demo';
                const resolved = await locate('demo');
                return resolved;
            }
            const binary = await binaryPath();
            const command = binary + ' subscribe --help';
            await execAsync(command);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) =>
                    finding.source.pattern === "WorkspaceConfiguration.get" &&
                    finding.sinkLocation.text === "execAsync(command)",
            ),
        ).toBe(true);
    });

    it.each(["resolve", "reject"])("keeps a tainted scalar alternative beside Promise.%s", async (method) => {
        const result = await scan(`
            async function select(value: string) {
                if (flag) return value;
                return Promise.${method}("fixed");
            }
            exec(await select(process.env.INPUT));
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each(["await", "then"])(
        "keeps observed scalar returns when another branch is unresolved (%s)",
        async (consumer) => {
            const result = await scan(`
            function externalFallback(): string { return (globalThis as any).unknownValue(); }
            async function select(value: string) {
                if (flag) return value;
                if (Date.now()) return Promise.resolve('fixed');
                return externalFallback();
            }
            ${consumer === "await" ? "exec(await select(process.env.INPUT));" : "select(process.env.INPUT).then(value => exec(value));"}
        `);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings).toHaveLength(1);
        },
    );

    it.each(["await", "then"])(
        "keeps observed scalar returns when another branch reaches the depth limit (%s)",
        async (consumer) => {
            const result = await scan(
                `
            function deepest() { return 'fixed'; }
            function fallback() { return deepest(); }
            async function select(value: string) {
                if (flag) return value;
                if (Date.now()) return Promise.resolve('fixed');
                return fallback();
            }
            ${consumer === "await" ? "exec(await select(process.env.INPUT));" : "select(process.env.INPUT).then(value => exec(value));"}
        `,
                2,
            );
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings).toHaveLength(1);
        },
    );

    it.each(["map", "filter"])("keeps the lexical depth budget for an inline Array.%s callback", async (method) => {
        const result = await scan(
            `
            function command() { return vscode.workspace.getConfiguration('demo').get<string>('command'); }
            function execute() { exec(command()); }
            function run() { execute(); }
            ['one'].${method}(() => { run(); return 'fixed'; });
        `,
            3,
        );
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("bounds named recursive array callbacks", async () => {
        const result = await scan(
            `
            function recurse(value: string) { return [value].map(recurse); }
            ['fixed'].map(recurse);
        `,
            3,
        );
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("does not taint the separately retained clean Promise alternative", async () => {
        const result = await scan(`
            const fixed = Promise.resolve('fixed');
            async function select(value: string) {
                if (flag) return value;
                return fixed;
            }
            await select(process.env.INPUT);
            fixed.then(value => exec(value));
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("does not move rejected taint into a clean scalar fulfillment", async () => {
        const result = await scan(`
            async function select(value: string) {
                if (flag) return "fixed";
                return Promise.reject(value);
            }
            select(process.env.INPUT).then(value => exec(value));
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });
});
