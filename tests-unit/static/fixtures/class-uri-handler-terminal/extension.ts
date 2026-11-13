/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: Class-based URI handler → terminal.sendText
//
// Modeled after T226521666
//
// A class implements UriHandler. handleUri extracts a query param and passes
// it through a private method that sends it to a VS Code terminal.
import * as vscode from "vscode";

class DeeplinkHandlerToTerminalRCE implements vscode.UriHandler {
    handleUri(uri: vscode.Uri) {
        const cmd = uri.query;
        this.runCmdInTerminal(cmd);
    }

    private runCmdInTerminal(cmd: string) {
        const terminal = vscode.window.createTerminal({ name: cmd });
        terminal.show();
        terminal.sendText(cmd, true);
    }
}

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler(new DeeplinkHandlerToTerminalRCE())
    );
}
