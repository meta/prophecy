/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture (T288770813): Input is reduced to a number before being used
// This should NOT be detected as a vulnerability.
import { exec } from "child_process";
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const input = uri.query;
                // SAFE: numeric conversion removes shell syntax.
                const safe = Number(input);
                exec(`echo ${safe}`);
            },
        })
    );
}
