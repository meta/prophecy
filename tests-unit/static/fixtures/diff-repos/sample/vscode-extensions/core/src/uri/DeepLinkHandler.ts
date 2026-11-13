/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";

export default class DeepLinkHandler implements vscode.UriHandler {
    handleUri(uri: vscode.Uri): void {
        if (uri.path.substr(1) === "run-terminal-command") {
            void this.runTerminalCommand(uri.query);
        }
    }

    private async runTerminalCommand(cmdStr: string): Promise<void> {
        await vscode.commands.executeCommand("core.runTerminalCommand", cmdStr);
    }
}
