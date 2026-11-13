/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Semantically safe, but currently a known false positive because allowlist
// guards are not modeled.
import { exec } from "child_process";
import * as vscode from "vscode";

const ALLOWED_COMMANDS = ["status", "version", "help"];

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const action = uri.query;
                if (ALLOWED_COMMANDS.includes(action)) {
                    exec(`git ${action}`);
                }
            },
        })
    );
}
