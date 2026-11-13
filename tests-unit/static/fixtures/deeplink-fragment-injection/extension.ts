/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: deeplink fragment → shell injection via a terminal (D53663037)
//
// Models a deeplink handler that concatenates uri.fragment into a shell command
// string, allowing an attacker to inject arbitrary commands with || or ;
// separators.
//
// Example deeplink: vscode://publisher.demo/?log-view#x||open /System/Applications/Calculator.app
//
// Taint flow:
//   handleUri(uri) → uri.fragment → "demo-cli log-viewer " + fragment → terminal.sendText(cmd)
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const logUrl = uri.fragment;
                const cmd = "demo-cli log-viewer " + logUrl;
                const terminal = vscode.window.createTerminal("Demo");
                terminal.sendText(cmd);
            },
        })
    );
}
