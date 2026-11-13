/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: DebugConfiguration mixes execution-related and cosmetic fields.
// The sink checks execution-bearing properties, so taint in a session `name`
// is treated differently from taint in `initCommands`.
//
// Four of the five handlers below should be reported; `cosmeticName` should not.
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    // NOT reported: only the session label is attacker-controlled.
    vscode.commands.registerCommand("ext.cosmeticName", async (x: string) => {
        await vscode.debug.startDebugging(undefined, {
            type: "node",
            request: "launch",
            name: `Session ${x}`,
            program: "/fixed/app.js",
        });
    });

    // Reported: lldb-dap runs initCommands before attach (`platform shell`, `script`).
    vscode.commands.registerCommand("ext.initCommands", async (x: string) => {
        await vscode.debug.startDebugging(undefined, {
            type: "lldb",
            request: "attach",
            name: "fixed",
            initCommands: [x],
        });
    });

    // Reported: `program` is what gets executed.
    vscode.commands.registerCommand("ext.program", async (x: string) => {
        await vscode.debug.startDebugging(undefined, {
            type: "node",
            request: "launch",
            name: "fixed",
            program: x,
        });
    });

    // Reported: adapter redirection to an attacker-controlled host.
    vscode.commands.registerCommand("ext.connect", async (x: string) => {
        await vscode.debug.startDebugging(undefined, {
            type: "python",
            request: "attach",
            name: "fixed",
            connect: x,
        });
    });

    // Reported: whole config tainted, no property known — must not be suppressed.
    vscode.commands.registerCommand("ext.wholeConfig", async (x: vscode.DebugConfiguration) => {
        await vscode.debug.startDebugging(undefined, x);
    });

    vscode.window.registerUriHandler({
        handleUri(uri: vscode.Uri) {
            void vscode.commands.executeCommand("ext.cosmeticName", uri.query);
            void vscode.commands.executeCommand("ext.initCommands", uri.query);
            void vscode.commands.executeCommand("ext.program", uri.query);
            void vscode.commands.executeCommand("ext.connect", uri.query);
            void vscode.commands.executeCommand(
                "ext.wholeConfig",
                JSON.parse(uri.query)
            );
        },
    });
}
