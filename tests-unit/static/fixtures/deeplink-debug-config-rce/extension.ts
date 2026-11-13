/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: deeplink → debug config injection (D53746551)
//
// Models the attack where a debugger extension's deeplink handler parses a
// debug configuration from the URI query string and passes it to
// vscode.debug.startDebugging(). The attacker controls the configuration
// object, so execution-bearing fields like `runtimeExecutable` run arbitrary
// commands.
//
// Reproduction: vscode://publisher.debugger/debug?{"type":"node","request":"launch","name":"x","runtimeExecutable":"/bin/sh","runtimeArgs":["-c","id"]}
//
// Taint flow:
//   handleUri(uri) → uri.query → JSON.parse(query) → debug.startDebugging(config)
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const configStr = uri.query;
                const config = JSON.parse(configStr);
                vscode.debug.startDebugging(undefined, config);
            },
        })
    );
}
