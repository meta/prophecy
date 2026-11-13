/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: attacker-controlled file paths and file contents are distinct
// sink arguments (T288945940).
import * as fs from "fs";
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    vscode.window.registerUriHandler({
        async handleUri(uri: vscode.Uri) {
            // VULN: attacker-controlled destination paths.
            fs.writeFile(uri.fsPath, "fixed", () => {});
            fs.writeFileSync(uri.path, "fixed");
            await vscode.workspace.fs.writeFile(
                uri,
                new TextEncoder().encode("fixed"),
            );

            // Control: a fixed cache destination is a lower-severity integrity concern.
            fs.writeFileSync(
                "/tmp/cache.json",
                JSON.stringify({value: uri.query}),
            );
        },
    });
}
