/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: executeCommand → registerCommand bridge RCE (D74929992)
//
// Taint flows across the executeCommand bridge:
//   uriHandler.ts: handleUri(uri) → executeCommand('run-terminal-cmd', cmd)
//   extension.ts:  registerCommand('run-terminal-cmd', handler) → terminal.sendText(cmd)
import * as vscode from "vscode";
import { DeeplinkHandler } from "./uriHandler";

export function activate(context: vscode.ExtensionContext) {
    const handler = new DeeplinkHandler();
    context.subscriptions.push(
        vscode.window.registerUriHandler(handler)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand("run-terminal-cmd", (cmd: string) => {
            const terminal = vscode.window.createTerminal({ name: "Runner" });
            terminal.show();
            terminal.sendText(cmd, true);
        })
    );
}
