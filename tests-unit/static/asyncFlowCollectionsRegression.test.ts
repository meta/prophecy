/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { analyze } from "../../src/static/analyzer";
import { vscodeSpecWithEnvSource } from "./testUtils";

async function scan(body: string) {
    return analyze({
        source: `import { exec } from "child_process";
            import * as fs from "fs";
            import * as vscode from "vscode";
            declare const flag: boolean;
            export function activate() { ${body} }`,
        fileName: "/src/asyncFlowCollectionsRegression.ts",
        spec: vscodeSpecWithEnvSource,
        maxDepth: 8,
        outputFormat: "text",
    });
}

describe("asyncFlow source arrays with empty alternatives", () => {
    it("filters unknown configured elements rather than treating the empty fallback as exhaustive", async () => {
        const result = await scan(`
            const configurations = vscode.workspace.getConfiguration('demo').get<Array<{command: string}>>('commands') || [];
            const selected = configurations.filter(config => config.command !== '');
            exec(selected[0].command);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("retains configured elements through filter, spread push, helper return and object spread", async () => {
        const result = await scan(`
            function configurations() {
                const result: Array<{command: string}> = [];
                const values = vscode.workspace.getConfiguration('demo').get<Array<{command: string}>>('commands') || [];
                result.push(...values.filter(value => value.command !== ''));
                return result;
            }
            const config = {...configurations()[0], mode: 'fixed'};
            exec(config.command);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("preserves mapped object fields after sorting and a clean catch alternative", async () => {
        const result = await scan(`
            function entries() {
                try {
                    return fs.readdirSync('/workspace').filter(file => file.endsWith('.md'))
                        .map(file => ({name: file.replace(/\\.md$/, ''), label: 'fixed'}))
                        .sort((a, b) => a.name.localeCompare(b.name));
                } catch { return []; }
            }
            const rows = entries().map(entry => ({command: entry.name, label: entry.label}));
            exec(rows[0].command);
            exec(rows[0].label);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toBe("exec(rows[0].command)");
    });

    it("retains directory-entry names in a single-quoted HTML handler after partial HTML escaping", async () => {
        const result = await scan(`
            function entries() {
                try {
                    return fs.readdirSync('/workspace').filter(file => file.endsWith('.md'))
                        .map(file => ({name: file.replace(/\\.md$/, ''), modified: 0}))
                        .sort((a, b) => b.modified - a.modified);
                } catch { return []; }
            }
            function escapeHtml(value: string) {
                return value.replace(/&/g, '&amp;').replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
            }
            const markup = entries().map(entry => '<button onclick="remove(' + "'" +
                escapeHtml(entry.name) + "'" + ')">Remove</button>').join('');
            const panel = vscode.window.createWebviewPanel('demo', 'Demo', vscode.ViewColumn.One, {});
            panel.webview.html = markup;
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) =>
                    finding.source.pattern === "fs.readdirSync" && finding.sink.pattern === "vscode.Webview.html",
            ),
        ).toBe(true);
    });

    it("respects an overridden array sort with a clean result", async () => {
        const result = await scan(`
            const rows = fs.readdirSync('/workspace').map(file => ({name: file}));
            rows.sort = () => [{name: 'fixed'}];
            const sorted = rows.sort();
            exec(sorted[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("does not execute callbacks of a definitely empty array", async () => {
        const result = await scan(`
            const values: string[] = [];
            const commands = values.map(() => process.env.INPUT);
            exec(commands.join(''));
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("keeps a clean callback result clean for an unknown source array", async () => {
        const result = await scan(`
            const values = vscode.workspace.getConfiguration('demo').get<string[]>('commands') || [];
            const commands = values.map(() => 'fixed');
            exec(commands.join(''));
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });
});
