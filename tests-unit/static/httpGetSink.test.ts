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
        source: `import * as vscode from "vscode"; import * as http from "http"; import * as https from "https"; ${source}`,
        fileName: path.join(__dirname, "http-get-sink-input.ts"),
        spec: vscodeExtensionSpec,
        maxDepth: 5,
        outputFormat: "json",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings.map((finding) => `${finding.sink.name}:${finding.sinkLocation.line}`).sort();
}

describe("http.get and https.get", () => {
    it("reports a tainted URL like the matching request call", async () => {
        expect(
            await check(`
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { url: string }) => {
                    http.get(message.url, () => {});
                    https.get(message.url, { headers: {} }, () => {});
                    https.request(message.url, () => {});
                });
            }
        `),
        ).toEqual(["http_get:4", "https_get:5", "https_request:6"]);
    });

    it("does not report a fixed URL or an unrelated get method", async () => {
        expect(
            await check(`
            declare const cache: { get(key: string): string };
            export function activate(panel: vscode.WebviewPanel) {
                panel.webview.onDidReceiveMessage((message: { url: string; key: string }) => {
                    https.get("https://example.com/fixed", () => {});
                    cache.get(message.key);
                });
            }
        `),
        ).toEqual([]);
    });
});
