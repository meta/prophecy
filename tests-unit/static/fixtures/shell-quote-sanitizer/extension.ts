/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// T255562430: `handleUri` data flows through `shlex.quote` to `sendText`.
// Quoting `uri.query` after fixed `agent` stops shell injection, so it is reported
// as argument injection; quoting all of `uri.path` or passing quoted
// `uri.fragment` as `sh -c` code remains command execution.
import * as shlex from "shlex";
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const terminal = vscode.window.createTerminal("Agent");
                terminal.sendText(
                    `agent new --title ${shlex.quote(uri.query)}`
                );
                terminal.sendText(shlex.quote(uri.path));
                terminal.sendText(`sh -c ${shlex.quote(uri.fragment)}`);
            },
        })
    );
}
