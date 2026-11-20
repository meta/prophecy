/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

async function check(source: string) {
    const result = await analyze({
        source: `import * as vscode from "vscode"; import { exec } from "child_process"; ${source}`,
        fileName: path.join(__dirname, "handler-class-reference-input.ts"),
        spec: vscodeExtensionSpec,
        maxDepth: 5,
        outputFormat: "json",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings.map((finding) => `${finding.source.pattern} -> ${finding.sink.name}`);
}

const handler = `class Handler implements vscode.UriHandler { handleUri(uri: vscode.Uri) { exec(uri.query); } }`;

describe("handler classes constructed through a reference", () => {
    it("finds a handler class held by an object of optional implementations", async () => {
        expect(
            await check(`
            ${handler}
            const implementations = { Handler };
            const optional: Partial<typeof implementations> = { ...implementations };
            export function activate() {
                if (optional.Handler != null) vscode.window.registerUriHandler(new optional.Handler());
            }
        `),
        ).toEqual(["handleUri.uri -> exec"]);
    });

    it("finds a handler class held by a property, a const alias, and a variable", async () => {
        expect(
            await check(`
            ${handler}
            const registry = { uri: Handler };
            const Alias = Handler;
            const instance = new registry.uri();
            export function activate() {
                vscode.window.registerUriHandler(new registry.uri());
                vscode.window.registerUriHandler(new Alias());
                vscode.window.registerUriHandler(instance);
            }
        `),
        ).toEqual(["handleUri.uri -> exec"]);
    });

    it("finds a class expression", async () => {
        expect(
            await check(`
            const Handler = class implements vscode.UriHandler { handleUri(uri: vscode.Uri) { exec(uri.query); } };
            export function activate() { vscode.window.registerUriHandler(new Handler()); }
        `),
        ).toEqual(["handleUri.uri -> exec"]);
    });

    it("does not treat a constructor typed only by an interface as a handler class", async () => {
        expect(
            await check(`
            ${handler}
            declare const registry: { uri: new () => vscode.UriHandler };
            export function activate() { vscode.window.registerUriHandler(new registry.uri()); }
        `),
        ).toEqual([]);
    });
});
