/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: command injection through a template literal.
import { exec } from "child_process";
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const repo = uri.query;
                exec(`git clone ${repo} /tmp/repo`);
            },
        })
    );
}
