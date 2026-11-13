/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: interprocedural injection through a helper function.
import { exec } from "child_process";
import * as vscode from "vscode";

function runCommand(cmd: string) {
    exec(cmd);
}

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const userInput = uri.query;
                runCommand(userInput);
            },
        })
    );
}
