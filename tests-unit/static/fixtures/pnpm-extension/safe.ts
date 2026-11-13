/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import { exec } from "child_process";

// URI input reaches the handler, but never the shell command.
export function activate(context: vscode.ExtensionContext): void {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri): void {
                console.log(uri.query);
                exec("printf safe");
            },
        }),
    );
}
