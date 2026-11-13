/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: URI handler RCE via deeplink (based on T226521666)
import * as vscode from "vscode";
import { exec } from "child_process";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const prompt = uri.query;
                exec(prompt);
            },
        })
    );
}
