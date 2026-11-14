/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { TaintTracker } from "../../src/static/taint/taintTracker";
import { vscodeSpecWithEnvSource } from "./testUtils";

async function scan(body: string, maxDepth = 8) {
    return analyze({
        source: `import { exec } from "child_process";
            import * as fs from "fs";
            import * as vscode from "vscode";
            declare const flag: boolean;
            export function activate() { ${body} }`,
        fileName: "/src/asyncFlowCollectionsRegression.ts",
        spec: vscodeSpecWithEnvSource,
        maxDepth,
        outputFormat: "text",
    });
}

async function scanFiles(files: Record<string, string>) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sort-identity-"));
    try {
        fs.symlinkSync(path.resolve(__dirname, "../../node_modules"), path.join(directory, "node_modules"), "dir");
        fs.writeFileSync(
            path.join(directory, "tsconfig.json"),
            JSON.stringify({
                compilerOptions: {
                    target: "es2020",
                    module: "commonjs",
                    moduleResolution: "node",
                    types: ["node"],
                    skipLibCheck: true,
                },
                include: ["*.ts"],
            }),
        );
        for (const [name, source] of Object.entries(files)) fs.writeFileSync(path.join(directory, name), source);
        return await analyze({
            projectDir: directory,
            spec: vscodeSpecWithEnvSource,
            maxDepth: 8,
            outputFormat: "text",
            requireTypes: true,
        });
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
}

const sortedClassFieldFixture = `
    type Row = {name: string; folder: string};
    async function entries(): Promise<Row[]> {
        const names = await fs.promises.readdir('/workspace');
        const pending = names.map(async (name): Promise<Row | null> => {
            const folder = '/workspace/' + name;
            if (!(await fs.promises.stat(folder)).isDirectory()) return null;
            const document = JSON.parse(await fs.promises.readFile(folder + '/state.json', 'utf8'));
            if (document == null) return null;
            return {name: document.name, folder};
        });
        const rows = (await Promise.all(pending)).filter((row): row is Row => row != null);
        return rows.sort((a, b) => a.name.localeCompare(b.name));
    }
    class Client {
        private rows: Row[] = [];
        async load() {
            this.rows = await entries();
            fs.readFileSync(this.rows[0].folder);
            exec(this.rows[0].name);
        }
    }
    new Client().load();
`;

describe("asyncFlow source arrays with empty alternatives", () => {
    it("bounds semantic payload facts across repeated native sorts", async () => {
        const prototype = TaintTracker.prototype as any;
        const finish = prototype.finishHostCall;
        const counts: Array<{ total: number; distinct: number }> = [];
        const spy = jest.spyOn(prototype, "finishHostCall").mockImplementation(function (this: any, ...args: any[]) {
            const [expression, , taints] = args;
            if (expression.expression.getText().endsWith(".sort")) {
                counts.push({
                    total: taints?.length ?? 0,
                    distinct: new Set((taints ?? []).map((taint: any) => this.taintFactKey(taint))).size,
                });
            }
            return finish.apply(this, args);
        });
        try {
            const result = await scan(`
                const rows = [{name: fs.readFileSync('/one', 'utf8'), folder: 'fixed'}, {name: fs.readFileSync('/two', 'utf8'), folder: 'fixed'}];
                rows.sort((a, b) => a.name.localeCompare(b.name));
                rows.sort((a, b) => a.name.localeCompare(b.name));
                rows.sort((a, b) => a.name.localeCompare(b.name));
                rows.sort((a, b) => a.name.localeCompare(b.name));
                exec(rows[0].name);
                exec(rows[0].folder);
            `);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(
                result.findings.filter((finding) => finding.sinkLocation.text === "exec(rows[0].name)"),
            ).toHaveLength(1);
            expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(rows[0].folder)")).toBe(false);
            expect(counts).toHaveLength(4);
            for (const count of counts) expect(count.total).toBe(count.distinct);
            expect(new Set(counts.map((count) => count.distinct)).size).toBe(1);
        } finally {
            spy.mockRestore();
        }
    });

    it.each([
        "(Array as any).prototype.sort = function() { return unknown(this); };",
        "const Alias: any = Array; Alias.prototype.sort = function() { return unknown(this); };",
    ])("rejects type-erased native constructor replacement: %s", async (replacement) => {
        const result = await scan(`
            declare function unknown(value: unknown): any;
            ${replacement}
            const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}];
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([2, 3, 4])(
        "retains the selected field after cross-element comparator writes with %s elements",
        async (length) => {
            const result = await scan(`
            const rows = [${Array.from({ length }, () => "{x: 'fixed', y: 'fixed'}").join(",")}];
            const sorted = rows.sort((a, b) => { a.x = b.y; a.y = fs.readFileSync('/state', 'utf8'); return 0; });
            exec(sorted[0].x);
        `);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(sorted[0].x)")).toBe(true);
        },
    );

    it("retains conservative sort qualification around opaque constructor use", async () => {
        const result = await scan(`
            class Client { create() { return new (this.constructor as any)(); } }
            const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}];
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([
        "export const prototype = Array.prototype;",
        "const prototype = Array.prototype; export {prototype};",
        "const prototype = Array.prototype; export default prototype;",
        "export const exposed = {prototype: Array.prototype};",
    ])("rejects exported prototype aliases across source files: %s", async (declaration) => {
        const aggregate = declaration.includes("exposed");
        const result = await scanFiles({
            "values.ts": declaration,
            "bridge.ts": aggregate
                ? "export {exposed} from './values';"
                : declaration.includes("export default")
                  ? "export {default as prototype} from './values';"
                  : "export {prototype} from './values';",
            "extension.ts": `
                import {exec} from 'child_process'; import * as fs from 'fs';
                import {${aggregate ? "exposed" : "prototype"}} from './bridge';
                declare function unknown(value: unknown): any;
                export function activate() {
                    ${aggregate ? "exposed.prototype" : "prototype"}.sort = function() { return unknown(this); };
                    const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}];
                    exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
                }
            `,
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("preserves shared array slot writes through an incomplete return", async () => {
        const result = await scan(
            `
            const queue = ['fixed'];
            function nested() { return 0; }
            function getQueue() { nested(); return queue; }
            const returned = getQueue();
            returned[0] = fs.readFileSync('/state', 'utf8');
            exec(queue[0]);
        `,
            1,
        );
        expect(result.syntaxErrors).toEqual([]);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(queue[0])")).toBe(true);
    });

    it("keeps JSON names separate from directory paths through async sorted class fields", async () => {
        const result = await scan(sortedClassFieldFixture);
        expect(result.skippedEntryPoints).toEqual([]);
        const paths = result.findings.filter(
            (finding) => finding.sinkLocation.text === "fs.readFileSync(this.rows[0].folder)",
        );
        expect(paths.some((finding) => finding.source.pattern === "fs.readFile")).toBe(false);
        expect(paths.some((finding) => finding.source.pattern === "fs.readdir")).toBe(true);
        expect(
            result.findings.some(
                (finding) =>
                    finding.source.pattern === "fs.readFile" && finding.sinkLocation.text === "exec(this.rows[0].name)",
            ),
        ).toBe(true);
    });
    it("preserves legacy sorted-array length provenance at resource sinks", async () => {
        const result = await scan(`
            const files = fs.readdirSync('/workspace').filter(file => file.endsWith('.py')).sort();
            fs.readFileSync('/cache/' + files.length);
            const parts = new Array<string>(files.length);
            fs.writeFileSync('/cache/' + parts.join('|'), 'fixed');
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        for (const sink of ["fs.readFileSync", "fs.writeFileSync"]) {
            expect(
                result.findings.some(
                    (finding) => finding.source.pattern === "fs.readdirSync" && finding.sink.pattern === sink,
                ),
            ).toBe(true);
        }
    });

    it("widens sorted positions without copying the array receiver", async () => {
        const result = await scan(`
            const rows = [{name: 'fixed', folder: 'fixed'}, {name: process.env.INPUT, folder: 'fixed'}];
            const alias = rows;
            const sorted = rows.sort((a, b) => a.name.localeCompare(b.name));
            exec(alias[0].name);
            sorted[0].folder = fs.readFileSync('/state', 'utf8');
            exec(rows[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(alias[0].name)")).toBe(true);
        expect(
            result.findings.some(
                (finding) =>
                    finding.sinkLocation.text === "exec(rows[0].folder)" &&
                    finding.source.pattern === "fs.readFileSync",
            ),
        ).toBe(true);
    });

    it("does not assume every sorted object is cleaned by a comparator", async () => {
        const result = await scan(`
            const first = {name: fs.readFileSync('/one', 'utf8')};
            const second = {name: fs.readFileSync('/two', 'utf8')};
            const rows = [first, second];
            rows.sort((a, b) => { a.name = 'fixed'; return 0; });
            exec(rows[0].name);
            exec(first.name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(rows[0].name)")).toBe(true);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(first.name)")).toBe(true);
    });

    it("retains default-sort object coercion mutations", async () => {
        const result = await scan(`
            const rows = [
                {name: fs.readFileSync('/one', 'utf8'), folder: 'fixed', toString() { this.folder = this.name; return 'x'; }},
                {name: fs.readFileSync('/two', 'utf8'), folder: 'fixed', toString() { this.folder = this.name; return 'y'; }},
            ];
            rows.sort();
            exec(rows[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(rows[0].folder)")).toBe(true);
    });

    it("analyzes both comparator parameters and their field mutations without using its return as elements", async () => {
        const result = await scan(`
            const rows = [{name: process.env.INPUT, folder: 'fixed'}, {name: 'fixed', folder: 'fixed'}];
            rows.sort((a, b) => {
                exec(a.name);
                exec(b.name);
                a.folder = b.name;
                b.folder = a.name;
                return process.env.ORDER as any;
            });
            exec(rows[0].folder);
            exec(rows[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        for (const sink of ["exec(a.name)", "exec(b.name)", "exec(rows[0].folder)", "exec(rows[0].name)"]) {
            expect(result.findings.some((finding) => finding.sinkLocation.text === sink)).toBe(true);
        }
        expect(result.findings.some((finding) => finding.sourceLocation.text === "process.env.ORDER")).toBe(false);
    });

    it.each(["===", "!=="])(
        "does not confuse a strict prototype identity comparison with an escape: %s",
        async (operator) => {
            const result = await scan(`
                const prototype = Object.getPrototypeOf([]);
                if (prototype ${operator} (flag ? Array.prototype : Object.prototype)) { void 0; }
                ${sortedClassFieldFixture}
            `);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings).toHaveLength(3);
            expect(
                result.findings.some(
                    (finding) =>
                        finding.source.pattern === "fs.readFile" &&
                        finding.sinkLocation.text === "fs.readFileSync(this.rows[0].folder)",
                ),
            ).toBe(false);
            expect(
                result.findings.some(
                    (finding) =>
                        finding.source.pattern === "fs.readdir" &&
                        finding.sinkLocation.text === "fs.readFileSync(this.rows[0].folder)",
                ),
            ).toBe(true);
        },
    );

    it("retains comparator slot reassignment", async () => {
        const result = await scan(`
            const rows = ['fixed', 'fixed'];
            rows.sort(() => { rows[0] = process.env.INPUT; return 0; });
            exec(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([
        "const C = Array; C.prototype.sort = function() { return unknown(this); };",
        "const C = Array; const prototype = C.prototype; prototype.sort = function() { return unknown(this); };",
        "globalThis.Array.prototype.sort = function() { return unknown(this); };",
    ])("keeps prototype replacement via aliases conservative: %s", async (replacement) => {
        const result = await scan(`
            declare function unknown(value: unknown): any;
            ${replacement}
            const rows = [{name: process.env.INPUT, folder: 'fixed'}];
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([
        "[].constructor.prototype.sort = function() { return unknown(this); };",
        "const holder = {ctor: [].constructor}; holder.ctor.prototype.sort = function() { return unknown(this); };",
        "Object.getPrototypeOf([]).sort = function() { return unknown(this); };",
        "[].__proto__.sort = function() { return unknown(this); };",
        "[]['__proto__'].sort = function() { return unknown(this); };",
        "const prototype = Object.getPrototypeOf([]); const holder = {prototype}; unknown(holder);",
    ])("keeps unnamed array prototype replacements conservative: %s", async (replacement) => {
        const result = await scan(`
            declare function unknown(value: unknown): any;
            ${replacement}
            const rows = [{name: process.env.INPUT, folder: 'fixed'}];
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("keeps an array escaped to an unresolved mutator conservative", async () => {
        const result = await scan(`
            type Row = {name: string; folder: string};
            declare function mutate(rows: Row[]): void;
            const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}, {name: 'fixed', folder: 'fixed'}];
            mutate(rows);
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) =>
                    finding.sinkLocation.text === "exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder)",
            ),
        ).toBe(true);
    });

    it("keeps comparator object escapes to unresolved mutators conservative", async () => {
        const result = await scan(`
            type Row = {name: string; folder: string};
            declare function mutateRow(row: Row): void;
            const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}, {name: 'fixed', folder: 'fixed'}];
            rows.sort((a, b) => { mutateRow(a); return a.name.localeCompare(b.name); });
            exec(rows[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(rows[0].folder)")).toBe(true);
    });

    it("does not trust an overridden Promise all producer before native sort", async () => {
        const result = await scan(`
            const name = fs.readFileSync('/state', 'utf8');
            Promise.all = async () => [{name: 'fixed', folder: name}] as any;
            async function load() {
                const rows = await Promise.all([{name, folder: 'fixed'}]);
                const sorted = rows.sort((a, b) => a.name.localeCompare(b.name));
                exec(sorted[0].folder);
            }
            load();
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(sorted[0].folder)")).toBe(true);
    });

    it("keeps a comparator truncated at the call depth limit conservative", async () => {
        const result = await scan(
            `
            function load() {
                const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}, {name: 'fixed', folder: 'fixed'}];
                function compare(a: {name: string; folder: string}, b: {name: string; folder: string}) {
                    a.folder = a.name; return 0;
                }
                rows.sort(compare);
                exec(rows[0].folder);
            }
            load();
        `,
            1,
        );
        expect(result.findings.some((finding) => finding.sinkLocation.text === "exec(rows[0].folder)")).toBe(true);
    });

    it("keeps an array escaped through an unresolved receiver method conservative", async () => {
        const result = await scan(`
            const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}, {name: 'fixed', folder: 'fixed'}];
            const holder = {rows, update: undefined as unknown as () => void};
            holder.update();
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) =>
                    finding.sinkLocation.text === "exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder)",
            ),
        ).toBe(true);
    });

    it("retains captured receiver mutations from a named comparator", async () => {
        const result = await scan(`
            const rows = [{name: 'fixed'}, {name: 'fixed'}];
            function compare(a: {name: string}, b: {name: string}) {
                rows.push({name: fs.readFileSync('/state', 'utf8')});
                return a.name.localeCompare(b.name);
            }
            exec(rows.sort(compare)[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("fs.readFileSync");
    });

    it("keeps selected element aliases across sorting and later mutation", async () => {
        const result = await scan(`
            const row = {name: 'fixed', folder: 'fixed'};
            const rows = [row];
            const sorted = rows.sort();
            row.folder = process.env.INPUT;
            exec(sorted[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("retains attacker data returned by an overridden sort", async () => {
        const result = await scan(`
            const rows = [{name: 'fixed'}];
            rows.sort = () => [{name: process.env.INPUT}];
            exec(rows.sort()[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("retains unknown and mixed return alternatives rather than trusting a surviving array", async () => {
        const result = await scan(`
            declare function unknown(value: string): Array<{name: string}>;
            function entries() {
                if (flag) return [{name: 'fixed'}];
                return unknown(process.env.INPUT);
            }
            exec(entries().sort()[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("does not treat a replaced Array prototype method as native", async () => {
        const result = await scan(`
            declare function unknown(value: unknown): any;
            Array.prototype.sort = function() { return unknown(this); };
            const rows = [{name: process.env.INPUT, folder: 'fixed'}];
            exec(rows.sort((a, b) => a.name.localeCompare(b.name))[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("analyzes an inherited in-program sort instead of applying a native model", async () => {
        const result = await scan(`
            class Rows extends Array<{name: string}> {
                sort() { return [{name: process.env.INPUT}] as this; }
            }
            exec(new Rows().sort()[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("retains unresolved comparator alternatives beside a known callback", async () => {
        const result = await scan(`
            type Row = {name: string; folder: string};
            declare const externalCompare: (a: Row, b: Row) => number;
            const compare = flag ? ((a: Row, b: Row) => 0) : externalCompare;
            const rows = [{name: fs.readFileSync('/state', 'utf8'), folder: 'fixed'}, {name: 'fixed', folder: 'fixed'}];
            fs.readFileSync(rows.sort(compare)[0].folder);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) => finding.sinkLocation.text === "fs.readFileSync(rows.sort(compare)[0].folder)",
            ),
        ).toBe(true);
    });

    it("keeps unknown comparator passthrough conservative", async () => {
        const result = await scan(`
            declare const compare: (a: {name: string}, b: {name: string}) => number;
            const rows = [{name: process.env.INPUT}];
            exec(rows.sort(compare)[0].name);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

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
