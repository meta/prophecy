/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as cp from "child_process";
import * as path from "path";
import * as vscode from "vscode";

export function runCommand(command: string, cwd?: string): Promise<string> {
    return new Promise((resolve, reject) => {
        cp.exec(command, { cwd }, (error, output) => {
            if (error) reject(error);
            else resolve(output);
        });
    });
}

export function runTool(args: string): Promise<string> {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? ".";
    const tool = vscode.workspace.getConfiguration().get<string | null>("demo.toolPath") ??
        path.join(root, "scripts", "bin", "tool");
    return runCommand(`${tool} ${args}`, root);
}
