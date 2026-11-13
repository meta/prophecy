/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: helper reached through a spread object
//
// A webview message reaches `runTool` through `Extensions.runTool`, where
// `Extensions` spreads `Registry`, a cast of an object literal whose shorthand
// properties name imported helpers (extensionsApi.ts → registry.ts → helpers.ts).
// `lookupFlag` receives the same message but has no sink: negative control.
import * as vscode from "vscode";
import { Extensions } from "./extensionsApi";

export function activate(context: vscode.ExtensionContext) {
    const panel = vscode.window.createWebviewPanel("demo", "Demo", vscode.ViewColumn.One, {});
    context.subscriptions.push(
        panel.webview.onDidReceiveMessage((message: { args: string[]; cwd: string; name: string }) => {
            void Extensions.runTool?.(message.args, message.cwd);
            void Extensions.lookupFlag?.(message.name);
        }),
    );
}
