/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Terminal wrapper — the final sink.
import * as vscode from "vscode";

export function executeInTerminal(cmd: string) {
    const terminal = vscode.window.createTerminal({ name: "Deeplink" });
    terminal.show();
    terminal.sendText(cmd, true);
}
