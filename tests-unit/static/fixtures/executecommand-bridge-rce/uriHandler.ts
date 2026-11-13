/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// URI handler that dispatches tainted input through executeCommand.
import * as vscode from "vscode";

export class DeeplinkHandler implements vscode.UriHandler {
    handleUri(uri: vscode.Uri) {
        const cmd = uri.query;
        vscode.commands.executeCommand("run-terminal-cmd", cmd);
    }
}
