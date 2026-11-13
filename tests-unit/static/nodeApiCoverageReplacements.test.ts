/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

async function scan(body: string) {
    const result = await analyze({
        source: `import * as vscode from 'vscode'; import {exec} from 'child_process';
            export function activate() {
                vscode.window.registerUriHandler({async handleUri(uri: vscode.Uri) {
                    const extra = require('fs-extra') as any;
                    ${body}
                }});
            }`,
        fileName: path.join(__dirname, "nodeApiCoverageReplacements-input.ts"),
        spec: vscodeExtensionSpec,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings.filter((finding) => finding.sink.name === "exec");
}

describe("nodeApiCoverage replaced file functions", () => {
    it.each([
        "extra.readFile = value => value; exec(extra.readFile(uri.query));",
        "extra.readFile = value => value; const read = extra.readFile; exec(read(uri.query));",
        "function identity(value: string) {return value;} extra.readFile = identity; exec(extra.readFile(uri.query));",
        "extra['readFile'] = value => value; exec(extra['readFile'](uri.query));",
    ])("does not box a known synchronous replacement as a native Promise: %s", async (body) => {
        const findings = await scan(body);
        expect(findings).toHaveLength(1);
        expect(findings[0].source.pattern).not.toBe("fs.readFile");
        expect(findings[0].propagationChain.some((step) => step.description.includes("query"))).toBe(true);
    });

    it("does not introduce file content from a synchronous replacement at a fixed argument", async () => {
        expect(
            await scan(`
            extra.readFile = value => value;
            const read = extra.readFile;
            exec(read('fixed'));
        `),
        ).toEqual([]);
    });

    it.each([
        "extra.readFile = async () => 'fixed'; exec(await extra.readFile('/fixed'));",
        "extra.readFile = async () => 'fixed'; const read = extra.readFile; exec(await read('/fixed'));",
    ])("does not grant file-source identity to a local async replacement: %s", async (body) => {
        expect(await scan(body)).toEqual([]);
    });

    it.each([
        "extra.readFile = async value => value; exec(await extra.readFile(uri.query));",
        "extra.readFile = async value => value; const read = extra.readFile; exec(await read(uri.query));",
    ])("preserves original provenance through a local async replacement: %s", async (body) => {
        const findings = await scan(body);
        expect(findings).toHaveLength(1);
        expect(findings[0].source.pattern).not.toBe("fs.readFile");
    });

    it("keeps an original native function captured before replacement", async () => {
        const findings = await scan(`
            const read = extra.readFile;
            extra.readFile = value => value;
            exec(await read('/fixed', 'utf8'));
        `);
        expect(findings.map((finding) => finding.source.pattern)).toEqual(["fs.readFile"]);
    });

    it("separates aliases captured before and after the same replacement", async () => {
        const findings = await scan(`
            const original = extra.readFile;
            extra.readFile = value => value;
            const replacement = extra.readFile;
            exec(await original('/fixed', 'utf8'));
            exec(replacement(uri.query));
        `);
        expect(findings).toHaveLength(2);
        expect(findings[0].source.pattern).toBe("fs.readFile");
        expect(findings[1].source.pattern).not.toBe("fs.readFile");
    });
});
