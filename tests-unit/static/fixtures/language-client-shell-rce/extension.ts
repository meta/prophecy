/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: workspace setting → language server argv with shell: true (T271372254)
//
// A malicious checkout ships .vscode/settings.json with
// {"demo.lazyMode": "; touch /tmp/marker;"}. The extension starts its language
// server through vscode-languageclient, which spawns `serverOptions.command`
// with `serverOptions.args` and `serverOptions.options`. With `shell: true`,
// Node joins argv into one shell command line. This test checks the static
// flow to the constructor, not runtime activation or restricted-mode behavior.
//
// Taint flow:
//   getConfig() → config.get("lazyMode") → createClient(config)
//   → ["--lazy-mode", config.lazyMode] → serverOptions.args
//   → new LanguageClient(...) → LanguageClientEx constructor → super(..., serverOptions, ...)
import * as vscode from "vscode";
import { DemoClient } from "./client";

export function activate(context: vscode.ExtensionContext) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (folder == null) return;
    context.subscriptions.push(
        new DemoClient({
            workspaceRoot: folder.uri.fsPath,
            getConfig: () => {
                const config = vscode.workspace.getConfiguration("demo", folder.uri);
                return {
                    lazyMode: config.get<string | null>("lazyMode", null),
                    stopOnExit: config.get<boolean>("stopOnExit", true),
                };
            },
        })
    );
}
