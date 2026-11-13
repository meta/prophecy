/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";

async function scan(source: string) {
    const result = await analyze({
        source,
        fileName: path.join(__dirname, "composed-file-source-input.ts"),
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

const imports = `import * as vscode from "vscode"; import {exec} from "node:child_process";`;

describe("Composed file source identity", () => {
    it.each([
        ["fs", "readFile"],
        ["node:fs", "readFile"],
        ["fs", "read"],
        ["node:fs", "read"],
    ])("does not treat %s %s callback returns or errors as file contents", async (module, name) => {
        const findings = await scan(`${imports}
            import {readFile as ${name}} from "${module}";
            export function activate() {
                const handle = ${name}("/fixed", (error, data) => { exec(error as any); });
                exec(handle as any);
            }
        `);
        expect(findings).toEqual([]);
    });

    it.each(["fs", "node:fs"])("retains %s callback data under the default preset", async (module) => {
        const findings = await scan(`${imports}
            import {readFile as read} from "${module}";
            export function activate() {
                read("/fixed", (error, data) => exec(data.toString()));
            }
        `);
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([["exec", "fs.readFile.data"]]);
    });

    it.each(["fs/promises", "node:fs/promises"])(
        "retains %s promise data without a VS Code source label",
        async (module) => {
            const findings = await scan(`${imports}
            import {readFile as read} from "${module}";
            export async function activate() { exec(String(await read("/fixed", "utf8"))); }
        `);
            expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([["exec", "fs.readFile"]]);
        },
    );

    it("retains genuine VS Code promise content through a captured method", async () => {
        const findings = await scan(`${imports}
            export async function activate() {
                const read = vscode.workspace.fs.readFile;
                exec(String(await read(vscode.Uri.file("/fixed"))));
            }
        `);
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([
            ["exec", "vscode.workspace.fs.readFile"],
        ]);
    });

    it("does not retain a source identity after replacing the read method", async () => {
        const findings = await scan(`${imports}
            export async function activate() {
                vscode.workspace.fs.readFile = async () => new Uint8Array();
                const read = vscode.workspace.fs.readFile;
                exec(String(await read(vscode.Uri.file("/fixed"))));
            }
        `);
        expect(findings).toEqual([]);
    });

    it("preserves a previously captured read after replacing the namespace method", async () => {
        const findings = await scan(`${imports}
            export async function activate() {
                const read = vscode.workspace.fs.readFile;
                vscode.workspace.fs.readFile = async () => new Uint8Array();
                exec(String(await read(vscode.Uri.file("/fixed"))));
            }
        `);
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([
            ["exec", "vscode.workspace.fs.readFile"],
        ]);
    });

    it("does not seed a same-named local function or object", async () => {
        const findings = await scan(`${imports}
            function readFile(path: string) { return "fixed"; }
            const local = {readFile(path: string) { return "fixed"; }};
            export function activate() { exec(readFile("/fixed")); exec(local.readFile("/fixed")); }
        `);
        expect(findings).toEqual([]);
    });
});
