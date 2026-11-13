/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// URI handler that dispatches tainted deeplink params via executeCommand.
import * as vscode from "vscode";

export class AIAssistantHandler implements vscode.UriHandler {
    handleUri(uri: vscode.Uri) {
        const task = uri.query;
        vscode.commands.executeCommand("assistant.runTask", task);
    }
}
