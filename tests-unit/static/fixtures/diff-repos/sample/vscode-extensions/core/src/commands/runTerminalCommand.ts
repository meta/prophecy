/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";

export function registerRunTerminalCommand(): vscode.Disposable {
    return vscode.commands.registerCommand("core.runTerminalCommand", (cmd: string) => {
        const terminal = vscode.window.createTerminal({ name: cmd });
        terminal.show();
        terminal.sendText(cmd, true);
    });
}
