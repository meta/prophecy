/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: command handler whose dangerous parameter is not the first one
// (modeled on an extension command that runs a subprocess for its caller).
//
// Taint flow:
//   handleUri(uri) → executeCommand("ext.runSubProcess", channelId, uri.authority, [uri.query])
//   → registerCommand("ext.runSubProcess", (channelId, command, args) => spawn(command, args))
//
// executeCommand(id, ...args) forwards every supplied argument to the handler.
// The benign parameter deliberately comes first so the bridge must preserve
// taint in non-zero parameter positions.
import * as vscode from "vscode";
import { spawn } from "child_process";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                void vscode.commands.executeCommand(
                    "ext.runSubProcess",
                    "channel",
                    uri.authority,
                    [uri.query]
                );
            },
        }),
        vscode.commands.registerCommand(
            "ext.runSubProcess",
            (channelId: string, command: string, args: Array<string>) => {
                // VULN: command/args reach spawn from a non-zero parameter index.
                return spawn(command, args);
            }
        )
    );
}
