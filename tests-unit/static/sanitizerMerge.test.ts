/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { deduplicateFindings } from "../../src/static/findingUtils";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

async function analyzeBody(body: string) {
    return analyze({
        source: `
            import * as shlex from "shlex";
            import * as vscode from "vscode";
            export function activate() {
                vscode.window.registerUriHandler({
                    handleUri(uri: vscode.Uri) {
                        const terminal = vscode.window.createTerminal("Demo");
                        ${body}
                    }
                });
            }
        `,
        fileName: "/src/extension.ts",
        spec: vscodeExtensionSpec,
        maxDepth: 5,
        outputFormat: "text",
    });
}

describe("Sanitizer-aware taint merging", () => {
    it.each([
        'uri.path ? "demo --name " + shlex.quote(uri.query) : uri.fragment',
        'uri.path ? uri.fragment : "demo --name " + shlex.quote(uri.query)',
    ])("keeps command execution when a same-handle branch is quoted: %s", async (command) => {
        const result = await analyzeBody(`terminal.sendText(${command});`);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.categories).toEqual(["rce"]);
    });

    it("keeps quoted-only branches as argument injection", async () => {
        const result = await analyzeBody(`
            const command = uri.path
                ? "demo --name " + shlex.quote(uri.query)
                : "demo --label " + shlex.quote(uri.fragment);
            terminal.sendText(command);
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.categories).toEqual(["arg_injection"]);
    });

    it.each([false, true])("does not merge a bare number with a composed value (reverse=%s)", async (reverse) => {
        const first = reverse ? 'count + "; sh -c "' : "count";
        const second = reverse ? "count" : 'count + "; sh -c "';
        const result = await analyzeBody(`
            const count = Number(uri.query);
            let part;
            if (uri.path) part = ${first};
            else part = ${second};
            terminal.sendText(\`demo --count \${part} \${shlex.quote(uri.fragment)}\`);
        `);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.categories).toEqual(["rce"]);
    });

    it.each([false, true])(
        "preserves element-wise quoting eligibility across branches (reverse=%s)",
        async (reverse) => {
            const first = reverse ? '["; sh -c", shlex.quote(uri.query)]' : "quoted";
            const second = reverse ? "quoted" : '["; sh -c", shlex.quote(uri.query)]';
            const result = await analyzeBody(`
            const quoted = [uri.query].map(shlex.quote);
            let args;
            if (uri.path) args = ${first};
            else args = ${second};
            terminal.sendText(\`demo \${args.join(" ")}\`);
        `);
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["rce"]);
        },
    );

    it("chooses RCE over argument injection regardless of result order", async () => {
        const safe = await analyzeBody('terminal.sendText("demo --name " + shlex.quote(uri.query));');
        const unsafe = await analyzeBody("terminal.sendText(uri.query);");
        expect(safe.findings[0].handle).toBe(unsafe.findings[0].handle);
        for (const findings of [
            [safe.findings[0], unsafe.findings[0]],
            [unsafe.findings[0], safe.findings[0]],
        ]) {
            expect(deduplicateFindings(findings)).toEqual([unsafe.findings[0]]);
        }
    });
});
