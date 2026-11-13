/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: WebSocket server RCE via cross-site WebSocket hijacking
// (T263572887)
//
// Models a WebSocket server with no authentication or origin checks. Received
// JSON supplies a VS Code command name and arguments. The static test checks
// the flow to executeCommand, not browser connectivity or execution of the
// selected command or any downstream terminal behavior.
//
// Taint flow:
//   ws.on('message', (data) => ...) → JSON.parse(data) →
//     message.params.arguments.command → vscode.commands.executeCommand(command)
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    const WebSocket = require("ws");
    const wss = new WebSocket.Server({ port: 0 });

    wss.on('connection', (ws: any) => {
        ws.on('message', (data: any) => {
            const message = JSON.parse(data);

            if (message.method === 'tools/call' &&
                message.params?.name === 'executeVscodeCommand') {
                const { command, args } = message.params.arguments;
                // VULNERABLE: attacker-controlled command name flows to executeCommand
                vscode.commands.executeCommand(command, ...(args ?? []));
            }
        });
    });
}
